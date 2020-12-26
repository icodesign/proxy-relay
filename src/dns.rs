use crate::TargetAddr;
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::prelude::*;
use trust_dns_resolver::proto::DnsHandle;
use trust_dns_resolver::{AsyncResolver, ConnectionProvider};

#[async_trait]
pub trait DNSResolver {
    async fn resolve(&self, addr: &TargetAddr) -> io::Result<Vec<SocketAddr>>;
}

pub struct TrustDNSResolver<'a, C: DnsHandle, P: ConnectionProvider<Conn = C>> {
    inner: &'a AsyncResolver<C, P>,
}

impl<'a, C: DnsHandle, P: ConnectionProvider<Conn = C>> TrustDNSResolver<'a, C, P> {
    pub fn new(inner: &'a AsyncResolver<C, P>) -> TrustDNSResolver<'a, C, P> {
        TrustDNSResolver { inner }
    }
}

#[async_trait]
impl<'a, C: DnsHandle, P: ConnectionProvider<Conn = C>> DNSResolver for TrustDNSResolver<'a, C, P> {
    async fn resolve(&self, addr: &TargetAddr) -> io::Result<Vec<SocketAddr>> {
        match addr {
            TargetAddr::Host(host, port) => match self.inner.lookup_ip(host.as_str()).await {
                Ok(result) => Ok(result.iter().map(|x| SocketAddr::new(x, *port)).collect()),
                Err(_e) => Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "Could't resolve host",
                )),
            },
            TargetAddr::Addr(addr) => Ok(vec![*addr]),
        }
    }
}
