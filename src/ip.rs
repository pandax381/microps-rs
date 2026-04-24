//! IP protocol.

use core::fmt;
use core::str::FromStr;

use crate::device::Device;
use crate::net;
use crate::util;

pub const IP_ADDR_LEN: usize = 4;
pub const IP_VERSION_IPV4: u8 = 4;
pub const IP_HDR_SIZE_MIN: usize = 20;

pub const IP_HDR_FLAG_MF: u16 = 0x2000; // more fragments flag
pub const IP_HDR_FLAG_DF: u16 = 0x4000; // don't fragment flag
pub const IP_HDR_FLAG_RF: u16 = 0x8000; // reserved
pub const IP_HDR_OFFSET_MASK: u16 = 0x1fff;

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
    print(data);
}

pub fn init() -> Result<(), ()> {
    net::register_protocol(net::PROTOCOL_TYPE_IP, input)?;
    Ok(())
}
