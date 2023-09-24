use crate::error::Error as ConfigError;
use socks5_proto::{
    handshake::{
        password, Method as HandshakeMethod, Request as HandshakeRequest,
        Response as HandshakeResponse,
    },
    Address, Command, Error as Socks5Error, ProtocolError, Reply, Request, Response, SOCKS_VERSION,
};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct Socks5 {
    server: SocketAddr,
    auth: Option<(Vec<u8>, Vec<u8>)>,
}

impl Socks5 {
    pub fn new(
        server: SocketAddr,
        username: Option<Vec<u8>>,
        password: Option<Vec<u8>>,
    ) -> Result<Self, ConfigError> {
        let auth: Option<(Vec<u8>, Vec<u8>)> = match (username, password) {
            (Some(username), Some(password)) => Some((username, password)),
            (None, None) => None,
            _ => return Err(ConfigError::InvalidSocks5Auth),
        };

        Ok(Self { server, auth })
    }

    pub async fn connect(&self, addr: Address) -> Result<TcpStream, Error> {
        let mut stream = TcpStream::connect(self.server).await?;
        log::debug!("[connect-socks5] start handshake");

        // 发送握手请求
        let hs_req = HandshakeRequest::new(vec![HandshakeMethod::NONE, HandshakeMethod::PASSWORD]);
        hs_req.write_to(&mut stream).await?;

        // 读取握手响应
        let hs_resp = HandshakeResponse::read_from(&mut stream).await?;
        if hs_resp.method == HandshakeMethod::PASSWORD {
            // 发送身份验证请求
            let auth = self
                .auth
                .clone()
                .ok_or(Error::new(ErrorKind::Other, "socks5 auth required"))?;
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
}
