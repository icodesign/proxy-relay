use crate::dns::DNSResolver;
use async_trait::async_trait;
use futures::future;
use std::net::SocketAddr;
use tls_api::{TlsConnector, TlsStream};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub mod dns;

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum TargetAddr {
    Host(String, u16),
    Addr(SocketAddr),
}

impl TargetAddr {
    pub fn from_host(host: &str, port: u16) -> TargetAddr {
        TargetAddr::Host(host.to_owned(), port)
    }

    pub fn from_addr(addr: SocketAddr) -> TargetAddr {
        TargetAddr::Addr(addr)
    }

    pub fn host(&self) -> String {
        match self {
            TargetAddr::Host(host, _) => host.to_owned(),
            TargetAddr::Addr(addr) => addr.ip().to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match *self {
            TargetAddr::Host(_, port) => port,
            TargetAddr::Addr(addr) => addr.port(),
        }
    }

    pub fn unwrap_addr(&self) -> SocketAddr {
        match *self {
            TargetAddr::Host(_, _) => panic!("Invalid destination type"),
            TargetAddr::Addr(addr) => addr,
        }
    }

    pub async fn connect<D: DNSResolver>(&self, resolver: &D) -> io::Result<TcpStream> {
        let remote_addr = resolver.resolve(self).await?;
        let mut err: io::Result<TcpStream> = Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Resolved addr is empty",
        ));
        for addr in remote_addr {
            match TcpStream::connect(addr).await {
                Ok(socket) => {
                    return Ok(socket);
                }
                Err(e) => {
                    err = Err(e);
                }
            }
        }
        err
    }
}

#[async_trait]
pub trait Connector<T: AsyncRead + AsyncWrite> {
    async fn connect(&self, addr: TargetAddr) -> io::Result<T>;
}

pub struct PlainConnector<D: DNSResolver>(D);

impl<D: DNSResolver> PlainConnector<D> {
    pub fn new(resolver: D) -> PlainConnector<D> {
        PlainConnector(resolver)
    }
}

#[async_trait]
impl<D: DNSResolver + Send + Sync> Connector<TcpStream> for PlainConnector<D> {
    async fn connect(&self, addr: TargetAddr) -> io::Result<TcpStream> {
        addr.connect(&self.0).await
    }
}

pub struct TLSConnector<D: DNSResolver, T: TlsConnector>(D, T);

impl<D: DNSResolver, T: TlsConnector> TLSConnector<D, T> {
    pub fn new(resolver: D, tls: T) -> TLSConnector<D, T> {
        TLSConnector(resolver, tls)
    }
}

#[async_trait]
impl<D: DNSResolver + Send + Sync, T: TlsConnector + Send + Sync> Connector<TlsStream<TcpStream>>
    for TLSConnector<D, T>
{
    async fn connect(&self, addr: TargetAddr) -> io::Result<TlsStream<TcpStream>> {
        let stream = addr.connect(&self.0).await?;
        let res = self.1.connect(&addr.host(), stream).await?;
        Ok(res)
    }
}

pub async fn relay<'a, L, R>(l: &'a mut L, r: &'a mut R) -> io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut lr, mut lw) = io::split(l);
    let (mut rr, mut rw) = io::split(r);
    return relay_split(&mut lr, &mut lw, &mut rr, &mut rw).await;
}

pub async fn relay_split<'a, LR, LW, RR, RW>(
    mut lr: &'a mut LR,
    mut lw: &'a mut LW,
    mut rr: &'a mut RR,
    mut rw: &'a mut RW,
) -> io::Result<(u64, u64)>
where
    LR: AsyncRead + Unpin + ?Sized,
    LW: AsyncWrite + Unpin + ?Sized,
    RR: AsyncRead + Unpin + ?Sized,
    RW: AsyncWrite + Unpin + ?Sized,
{
    let client_to_server = transfer(&mut lr, &mut rw);
    let server_to_client = transfer(&mut rr, &mut lw);
    return future::try_join(client_to_server, server_to_client).await;
}

pub async fn transfer<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let len = io::copy(reader, writer).await?;
    writer.shutdown().await?;
    Ok(len)
}
