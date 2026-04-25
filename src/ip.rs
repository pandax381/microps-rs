//! IP protocol.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::str::FromStr;

use spin::Mutex;

use crate::device::{Device, NetIface, ADDR_LEN, FAMILY_IP, FLAG_NEED_ARP};
use crate::net;
use crate::util;

pub const IP_ADDR_LEN: usize = 4;
pub const IP_VERSION_IPV4: u8 = 4;
pub const IP_HDR_SIZE_MIN: usize = 20;

pub const IP_HDR_FLAG_MF: u16 = 0x2000; // more fragments flag
pub const IP_HDR_FLAG_DF: u16 = 0x4000; // don't fragment flag
pub const IP_HDR_FLAG_RF: u16 = 0x8000; // reserved
pub const IP_HDR_OFFSET_MASK: u16 = 0x1fff;

pub const IP_PROTOCOL_ICMP: u8 = 1;
pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;

pub type ProtocolHandler = fn(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface);

struct Protocol {
    protocol: u8,
    handler: ProtocolHandler,
}

static PROTOCOLS: Mutex<Vec<Protocol>> = Mutex::new(Vec::new());

pub fn register_protocol(protocol: u8, handler: ProtocolHandler) -> Result<(), ()> {
    let mut protocols = PROTOCOLS.lock();
    if protocols.iter().any(|p| p.protocol == protocol) {
        crate::errorf!("already registered, protocol={}", protocol);
        return Err(());
    }
    protocols.push(Protocol { protocol, handler });
    crate::infof!("registered, protocol={}", protocol);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddr(pub [u8; IP_ADDR_LEN]);

impl IpAddr {
    pub const ANY: Self = Self([0; IP_ADDR_LEN]);
    pub const BROADCAST: Self = Self([0xff; IP_ADDR_LEN]);
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl FromStr for IpAddr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; IP_ADDR_LEN];
        let mut parts = s.split('.');
        for octet in &mut octets {
            *octet = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        }
        if parts.next().is_some() {
            return Err(());
        }
        Ok(IpAddr(octets))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpEndp {
    pub addr: IpAddr,
    pub port: u16,
}

impl IpEndp {
    pub fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }
}

impl fmt::Display for IpEndp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl FromStr for IpEndp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, port_str) = s.rsplit_once(':').ok_or(())?;
        let addr: IpAddr = addr_str.parse()?;
        let port: u16 = port_str.parse().map_err(|_| ())?;
        Ok(Self { addr, port })
    }
}

pub struct IpHdr<'a> {
    data: &'a [u8],
}

impl<'a> IpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < IP_HDR_SIZE_MIN {
            return None;
        }
        Some(Self { data })
    }

    pub fn vhl(&self) -> u8 {
        self.data[0]
    }

    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    pub fn ihl(&self) -> u8 {
        self.data[0] & 0x0f
    }

    pub fn hlen(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    pub fn tos(&self) -> u8 {
        self.data[1]
    }

    pub fn total(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn offset(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    pub fn src(&self) -> IpAddr {
        IpAddr([self.data[12], self.data[13], self.data[14], self.data[15]])
    }

    pub fn dst(&self) -> IpAddr {
        IpAddr([self.data[16], self.data[17], self.data[18], self.data[19]])
    }
}

pub struct IpIface {
    dev: Arc<Device>,
    unicast: IpAddr,
    netmask: IpAddr,
    broadcast: IpAddr,
}

impl IpIface {
    pub fn dev(&self) -> &Arc<Device> {
        &self.dev
    }

    pub fn unicast(&self) -> IpAddr {
        self.unicast
    }

    pub fn netmask(&self) -> IpAddr {
        self.netmask
    }

    pub fn broadcast(&self) -> IpAddr {
        self.broadcast
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        for i in 0..IP_ADDR_LEN {
            if (addr.0[i] & self.netmask.0[i]) != (self.unicast.0[i] & self.netmask.0[i]) {
                return false;
            }
        }
        true
    }
}

impl NetIface for IpIface {
    fn family(&self) -> u16 {
        FAMILY_IP
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

static IFACES: Mutex<Vec<Arc<IpIface>>> = Mutex::new(Vec::new());

pub struct IpRoute {
    pub network: IpAddr,
    pub netmask: IpAddr,
    pub nexthop: IpAddr,
    pub iface: Arc<IpIface>,
}

static ROUTES: Mutex<Vec<Arc<IpRoute>>> = Mutex::new(Vec::new());

pub fn route_add(
    network: IpAddr,
    netmask: IpAddr,
    nexthop: IpAddr,
    iface: Arc<IpIface>,
) -> Result<(), ()> {
    let route = Arc::new(IpRoute {
        network,
        netmask,
        nexthop,
        iface: iface.clone(),
    });
    ROUTES.lock().push(route);
    crate::infof!(
        "network={}, netmask={}, nexthop={}, dev={}",
        network,
        netmask,
        nexthop,
        iface.dev.name
    );
    Ok(())
}

pub fn route_lookup(dst: IpAddr) -> Option<Arc<IpRoute>> {
    let routes = ROUTES.lock();
    let mut best: Option<Arc<IpRoute>> = None;
    let mut best_prefix: i32 = -1;
    for route in routes.iter() {
        let matches = (0..IP_ADDR_LEN)
            .all(|i| (dst.0[i] & route.netmask.0[i]) == route.network.0[i]);
        if matches {
            let prefix: i32 = route
                .netmask
                .0
                .iter()
                .map(|b| b.count_ones() as i32)
                .sum();
            if prefix > best_prefix {
                best = Some(route.clone());
                best_prefix = prefix;
            }
        }
    }
    best
}

pub fn set_default_gateway(iface: &Arc<IpIface>, gw: IpAddr) -> Result<(), ()> {
    route_add(IpAddr::ANY, IpAddr::ANY, gw, iface.clone())
}

pub fn iface_select(addr: IpAddr) -> Option<Arc<IpIface>> {
    IFACES
        .lock()
        .iter()
        .find(|iface| iface.unicast == addr)
        .cloned()
}

fn build_packet(
    protocol: u8,
    data: &[u8],
    src: IpAddr,
    dst: IpAddr,
    id: u16,
) -> Result<Vec<u8>, ()> {
    let total = IP_HDR_SIZE_MIN + data.len();
    if total > u16::MAX as usize {
        crate::errorf!("too long, total={}", total);
        return Err(());
    }
    let mut buf = vec![0u8; total];
    buf[0] = (IP_VERSION_IPV4 << 4) | ((IP_HDR_SIZE_MIN / 4) as u8);
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 255;
    buf[9] = protocol;
    buf[12..16].copy_from_slice(&src.0);
    buf[16..20].copy_from_slice(&dst.0);
    let checksum = util::cksum16(&buf[..IP_HDR_SIZE_MIN], 0);
    buf[10..12].copy_from_slice(&checksum.to_ne_bytes());
    buf[IP_HDR_SIZE_MIN..].copy_from_slice(data);
    Ok(buf)
}

fn output_device(iface: &IpIface, buf: &[u8], target: IpAddr) -> Result<(), ()> {
    crate::debugf!("dev={}, len={}, target={}", iface.dev.name, buf.len(), target);
    let mut hwaddr = [0u8; ADDR_LEN];
    if iface.dev.flags() & FLAG_NEED_ARP != 0 {
        if target == iface.broadcast || target == IpAddr::BROADCAST {
            let alen = iface.dev.alen as usize;
            hwaddr[..alen].copy_from_slice(&iface.dev.broadcast[..alen]);
        } else {
            match crate::arp::resolve(iface, target)? {
                Some(mac) => {
                    let alen = iface.dev.alen as usize;
                    hwaddr[..alen].copy_from_slice(&mac.0[..alen]);
                }
                None => return Ok(()),
            }
        }
    }
    iface.dev.output(net::PROTOCOL_TYPE_IP, buf, &hwaddr)
}

pub fn output(protocol: u8, data: &[u8], src: IpAddr, dst: IpAddr) -> Result<(), ()> {
    crate::debugf!("{} => {}, protocol={}, len={}", src, dst, protocol, data.len());
    if src == IpAddr::ANY && dst == IpAddr::BROADCAST {
        crate::errorf!("source address is required for broadcast");
        return Err(());
    }
    let route = match route_lookup(dst) {
        Some(r) => r,
        None => {
            crate::errorf!("no route to host, dst={}", dst);
            return Err(());
        }
    };
    let iface = &route.iface;
    let nexthop = if route.nexthop != IpAddr::ANY {
        route.nexthop
    } else {
        dst
    };
    let src = if src == IpAddr::ANY {
        iface.unicast
    } else if src != iface.unicast {
        crate::errorf!(
            "source address mismatch, src={}, iface={}",
            src,
            iface.unicast
        );
        return Err(());
    } else {
        src
    };
    if (iface.dev.mtu as usize) < IP_HDR_SIZE_MIN + data.len() {
        crate::errorf!(
            "too long, dev={}, mtu={} < {}",
            iface.dev.name,
            iface.dev.mtu,
            IP_HDR_SIZE_MIN + data.len()
        );
        return Err(());
    }
    let id = crate::platform::random32() as u16;
    let buf = build_packet(protocol, data, src, dst, id)?;
    print(&buf);
    output_device(iface, &buf, nexthop)
}

pub fn iface_register(
    dev: &Arc<Device>,
    unicast: &str,
    netmask: &str,
) -> Result<Arc<IpIface>, ()> {
    let unicast: IpAddr = unicast.parse()?;
    let netmask: IpAddr = netmask.parse()?;
    let broadcast = IpAddr([
        unicast.0[0] | !netmask.0[0],
        unicast.0[1] | !netmask.0[1],
        unicast.0[2] | !netmask.0[2],
        unicast.0[3] | !netmask.0[3],
    ]);
    let iface = Arc::new(IpIface {
        dev: Arc::clone(dev),
        unicast,
        netmask,
        broadcast,
    });
    dev.add_iface(iface.clone())?;
    IFACES.lock().push(iface.clone());
    let network = IpAddr([
        unicast.0[0] & netmask.0[0],
        unicast.0[1] & netmask.0[1],
        unicast.0[2] & netmask.0[2],
        unicast.0[3] & netmask.0[3],
    ]);
    route_add(network, netmask, IpAddr::ANY, iface.clone())?;
    crate::infof!(
        "dev={}, unicast={}, netmask={}, broadcast={}",
        dev.name,
        unicast,
        netmask,
        broadcast
    );
    Ok(iface)
}

fn print(data: &[u8]) {
    if let Some(hdr) = IpHdr::new(data) {
        crate::printf!(
            "        vhl: 0x{:02x} [v: {}, hl: {} ({} bytes)]",
            hdr.vhl(),
            hdr.version(),
            hdr.ihl(),
            hdr.hlen()
        );
        crate::printf!("        tos: 0x{:02x}", hdr.tos());
        crate::printf!("      total: {}", hdr.total());
        crate::printf!("         id: {}", hdr.id());
        crate::printf!(
            "     offset: 0x{:04x} [flags=0x{:x}, offset={}]",
            hdr.offset(),
            hdr.offset() >> 13,
            hdr.offset() & 0x1fff
        );
        crate::printf!("        ttl: {}", hdr.ttl());
        crate::printf!("   protocol: {}", hdr.protocol());
        crate::printf!("        sum: 0x{:04x}", hdr.sum());
        crate::printf!("        src: {}", hdr.src());
        crate::printf!("        dst: {}", hdr.dst());
    }
    crate::printf!("{}", crate::util::HexDump(data));
}

fn input(data: &[u8], dev: &Device) {
    crate::debugf!("dev={}, len={}", dev.name, data.len());
    let hdr = match IpHdr::new(data) {
        Some(h) => h,
        None => {
            crate::errorf!("too short, len={}", data.len());
            return;
        }
    };
    if hdr.version() != IP_VERSION_IPV4 {
        crate::errorf!("not IPv4, version={}", hdr.version());
        return;
    }
    let hlen = hdr.hlen();
    if data.len() < hlen {
        crate::errorf!("header truncated, len={} < hlen={}", data.len(), hlen);
        return;
    }
    let total = hdr.total() as usize;
    if data.len() < total {
        crate::errorf!("total truncated, len={} < total={}", data.len(), total);
        return;
    }
    if util::cksum16(&data[..hlen], 0) != 0 {
        crate::errorf!("checksum error, sum=0x{:04x}", hdr.sum());
        return;
    }
    let offset = hdr.offset();
    if offset & IP_HDR_FLAG_MF != 0 || offset & IP_HDR_OFFSET_MASK != 0 {
        crate::errorf!("fragments does not support");
        return;
    }
    let net_iface = match dev.get_iface(FAMILY_IP) {
        Some(i) => i,
        None => return,
    };
    let iface = match net_iface.as_any().downcast_ref::<IpIface>() {
        Some(i) => i,
        None => return,
    };
    if hdr.dst() != iface.unicast
        && hdr.dst() != iface.broadcast
        && hdr.dst() != IpAddr::BROADCAST
    {
        return;
    }
    print(data);
    let handler = {
        let protocols = PROTOCOLS.lock();
        protocols
            .iter()
            .find(|p| p.protocol == hdr.protocol())
            .map(|p| p.handler)
    };
    if let Some(handler) = handler {
        handler(&hdr, &data[hlen..total], iface);
    } else {
        let icmp_data_len = hlen + core::cmp::min(8, total - hlen);
        let _ = crate::icmp::output(
            crate::icmp::ICMP_TYPE_DEST_UNREACH,
            crate::icmp::ICMP_CODE_PROTO_UNREACH,
            0,
            &data[..icmp_data_len],
            iface.unicast,
            hdr.src(),
        );
    }
}

pub fn init() -> Result<(), ()> {
    net::register_protocol(net::PROTOCOL_TYPE_IP, input)?;
    Ok(())
}
