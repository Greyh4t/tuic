use socks5_proto::{
    handshake::{
        password, Method as HandshakeMethod, Request as HandshakeRequest,
        Response as HandshakeResponse,
    },
    Address, Command, Error as Socks5Error, ProtocolError, Reply, Request, Response, SOCKS_VERSION,
};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;

mod config {
    use super::SocketAddr;
    use once_cell::sync::OnceCell;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static SERVER: OnceCell<SocketAddr> = OnceCell::new();
    static AUTH: OnceCell<(Vec<u8>, Vec<u8>)> = OnceCell::new();

    pub fn set_config(server: SocketAddr, auth: Option<(Vec<u8>, Vec<u8>)>) {
        INIT.call_once(|| {
            SERVER
                .set(server)
                .map_err(|_| "failed set socks5 config")
                .unwrap();
            if let Some(auth) = auth {
                AUTH.set(auth)
                    .map_err(|_| "failed set socks5 config")
                    .unwrap();
            }
        });
    }

    pub fn get_server() -> SocketAddr {
        return *SERVER.get().unwrap();
    }

    pub fn get_auth() -> Option<(Vec<u8>, Vec<u8>)> {
        if let Some(auth) = AUTH.get() {
            return Some((auth.0.clone(), auth.1.clone()));
        }
        return None;
    }

    pub fn is_inited() -> bool {
        INIT.is_completed()
    }
}

pub use config::*;
pub async fn connect(addr: Address) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(config::get_server()).await?;
    log::debug!("[connect-socks5] start handshake");

    // 发送握手请求
    let hs_req = HandshakeRequest::new(vec![HandshakeMethod::NONE, HandshakeMethod::PASSWORD]);
    hs_req.write_to(&mut stream).await?;

    // 读取握手响应
    let hs_resp = HandshakeResponse::read_from(&mut stream).await?;
    if hs_resp.method == HandshakeMethod::PASSWORD {
        // 发送身份验证请求
        let auth = get_auth().ok_or(Error::new(ErrorKind::Other, "socks5 auth required"))?;
        let req = password::Request::new(auth.0, auth.1);
        req.write_to(&mut stream).await?;

        // 读取身份验证响应
        let resp = password::Response::read_from(&mut stream).await?;
        if !resp.status {
            return Err(Error::new(ErrorKind::Other, "socks5 auth failed"));
        }
    } else if hs_resp.method != HandshakeMethod::NONE {
        return Err(Error::new(
            ErrorKind::Other,
            Socks5Error::Protocol(ProtocolError::NoAcceptableHandshakeMethod {
                version: SOCKS_VERSION,
                chosen_method: hs_resp.method,
                methods: hs_req.methods,
            }),
        ));
    }

    // 发送连接请求
    let req = Request::new(Command::Connect, addr);
    req.write_to(&mut stream).await?;

    // 读取连接响应
    let resp = Response::read_from(&mut stream).await?;
    if resp.reply != Reply::Succeeded {
        return Err(Error::new(
            ErrorKind::Other,
            Socks5Error::Protocol(ProtocolError::InvalidReply {
                version: SOCKS_VERSION,
                reply: resp.reply.into(),
            }),
        ));
    }

    log::debug!("[connect-socks5] connection established");
    Ok(stream)
}
