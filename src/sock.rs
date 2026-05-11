//! BSD-style socket API.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use spin::Mutex;

use crate::ip::{IpAddr, IpEndp};
use crate::{tcp, udp};

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const SOCK_STREAM: u8 = 1;
pub const SOCK_DGRAM: u8 = 2;

pub type SockDesc = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddrV4 {
    ip: IpAddr,
    port: u16,
}

impl SocketAddrV4 {
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

impl FromStr for SocketAddrV4 {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let endp: IpEndp = s.parse()?;
        Ok(SocketAddrV4::new(endp.addr, endp.port))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAddr {
    V4(SocketAddrV4),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::V4(v4) => v4.fmt(f),
        }
    }
}

impl FromStr for SocketAddr {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let v4: SocketAddrV4 = s.parse()?;
        Ok(SocketAddr::V4(v4))
    }
}

fn to_endp(addr: SocketAddr) -> Result<IpEndp, ()> {
    match addr {
        SocketAddr::V4(v4) => Ok(IpEndp::new(v4.ip(), v4.port())),
    }
}

fn from_endp(ep: IpEndp) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ep.addr, ep.port))
}

#[derive(Debug, Clone, Copy)]
struct Sock {
    family: u16,
    ty: u8,
    desc: usize,
}

static SOCKS: Mutex<Vec<Option<Sock>>> = Mutex::new(Vec::new());

fn sock_alloc(socks: &mut Vec<Option<Sock>>, sock: Sock) -> SockDesc {
    for (i, slot) in socks.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(sock);
            return i;
        }
    }
    let desc = socks.len();
    socks.push(Some(sock));
    desc
}

fn sock_get(desc: SockDesc) -> Option<Sock> {
    SOCKS.lock().get(desc).and_then(|s| s.as_ref()).copied()
}

pub fn open(family: u16, ty: u8) -> Result<SockDesc, ()> {
    if family != AF_INET {
        crate::errorf!("unsupported family: {}", family);
        return Err(());
    }
    let desc = match ty {
        SOCK_STREAM => tcp::socket()?,
        SOCK_DGRAM => udp::open().ok_or_else(|| {
            crate::errorf!("udp::open() failure");
        })?,
        _ => {
            crate::errorf!("unsupported type: {}", ty);
            return Err(());
        }
    };
    let mut socks = SOCKS.lock();
    let sock_desc = sock_alloc(&mut socks, Sock { family, ty, desc });
    crate::debugf!("desc={}, family={}, type={}", sock_desc, family, ty);
    Ok(sock_desc)
}

pub fn close(desc: SockDesc) -> Result<(), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    SOCKS.lock()[desc] = None;
    match sock.ty {
        SOCK_STREAM => tcp::close(sock.desc),
        SOCK_DGRAM => udp::close(sock.desc),
        _ => Err(()),
    }
}

pub fn bind(desc: SockDesc, addr: SocketAddr) -> Result<(), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.family != AF_INET {
        crate::errorf!("unsupported family: {}", sock.family);
        return Err(());
    }
    let endp = to_endp(addr)?;
    match sock.ty {
        SOCK_STREAM => tcp::bind(sock.desc, endp),
        SOCK_DGRAM => udp::bind(sock.desc, endp),
        _ => Err(()),
    }
}

pub fn listen(desc: SockDesc, backlog: usize) -> Result<(), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_STREAM {
        crate::errorf!("listen requires SOCK_STREAM");
        return Err(());
    }
    tcp::listen(sock.desc, backlog)
}

pub fn accept(desc: SockDesc) -> Result<(SockDesc, SocketAddr), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_STREAM {
        crate::errorf!("accept requires SOCK_STREAM");
        return Err(());
    }
    let (new_tcp_desc, remote_ep) = tcp::accept(sock.desc)?;
    let mut socks = SOCKS.lock();
    let new_sock_desc = sock_alloc(
        &mut socks,
        Sock {
            family: sock.family,
            ty: sock.ty,
            desc: new_tcp_desc,
        },
    );
    Ok((new_sock_desc, from_endp(remote_ep)))
}

pub fn connect(desc: SockDesc, addr: SocketAddr) -> Result<(), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_STREAM {
        crate::errorf!("connect requires SOCK_STREAM");
        return Err(());
    }
    let endp = to_endp(addr)?;
    tcp::connect(sock.desc, endp)
}

pub fn send(desc: SockDesc, data: &[u8]) -> Result<usize, ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_STREAM {
        crate::errorf!("send requires SOCK_STREAM");
        return Err(());
    }
    tcp::send(sock.desc, data)
}

pub fn recv(desc: SockDesc, buf: &mut [u8]) -> Result<usize, ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_STREAM {
        crate::errorf!("recv requires SOCK_STREAM");
        return Err(());
    }
    tcp::receive(sock.desc, buf)
}

pub fn sendto(desc: SockDesc, data: &[u8], addr: SocketAddr) -> Result<usize, ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_DGRAM {
        crate::errorf!("sendto requires SOCK_DGRAM");
        return Err(());
    }
    let endp = to_endp(addr)?;
    udp::sendto(sock.desc, data, endp)
}

pub fn recvfrom(desc: SockDesc, buf: &mut [u8]) -> Result<(usize, SocketAddr), ()> {
    let sock = sock_get(desc).ok_or_else(|| {
        crate::errorf!("sock not found, desc={}", desc);
    })?;
    if sock.ty != SOCK_DGRAM {
        crate::errorf!("recvfrom requires SOCK_DGRAM");
        return Err(());
    }
    let (remote_ep, n) = udp::recvfrom(sock.desc, buf).map_err(|_| ())?;
    Ok((n, from_endp(remote_ep)))
}
