//! Ethernet protocol.

use core::fmt;
use core::str::FromStr;

pub const ETHER_ADDR_LEN: usize = 6;
pub const ETHER_HDR_SIZE: usize = 14;

pub const ETHER_FRAME_SIZE_MIN: usize = 60;
pub const ETHER_FRAME_SIZE_MAX: usize = 1514;
pub const ETHER_PAYLOAD_SIZE_MIN: usize = ETHER_FRAME_SIZE_MIN - ETHER_HDR_SIZE;
pub const ETHER_PAYLOAD_SIZE_MAX: usize = ETHER_FRAME_SIZE_MAX - ETHER_HDR_SIZE;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86dd;

pub const ETHER_ADDR_ANY: EtherAddr = EtherAddr([0; ETHER_ADDR_LEN]);
pub const ETHER_ADDR_BROADCAST: EtherAddr = EtherAddr([0xff; ETHER_ADDR_LEN]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EtherAddr(pub [u8; ETHER_ADDR_LEN]);

impl fmt::Display for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for EtherAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for EtherAddr {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; ETHER_ADDR_LEN];
        let mut iter = s.split(':');
        for byte in &mut bytes {
            let part = iter.next().ok_or(())?;
            *byte = u8::from_str_radix(part, 16).map_err(|_| ())?;
        }
        if iter.next().is_some() {
            return Err(());
        }
        Ok(Self(bytes))
    }
}

pub struct EtherHdr<'a> {
    data: &'a [u8],
}

impl<'a> EtherHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ETHER_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn dst(&self) -> EtherAddr {
        let mut a = [0u8; ETHER_ADDR_LEN];
        a.copy_from_slice(&self.data[0..6]);
        EtherAddr(a)
    }

    pub fn src(&self) -> EtherAddr {
        let mut a = [0u8; ETHER_ADDR_LEN];
        a.copy_from_slice(&self.data[6..12]);
        EtherAddr(a)
    }

    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }
}

fn type_name(ethertype: u16) -> &'static str {
    match ethertype {
        ETHER_TYPE_IP => "IP",
        ETHER_TYPE_ARP => "ARP",
        ETHER_TYPE_IPV6 => "IPv6",
        _ => "Unknown",
    }
}

pub fn print(frame: &[u8]) {
    if let Some(hdr) = EtherHdr::new(frame) {
        crate::printf!("        src: {}", hdr.src());
        crate::printf!("        dst: {}", hdr.dst());
        crate::printf!(
            "       type: 0x{:04x} ({})",
            hdr.ethertype(),
            type_name(hdr.ethertype())
        );
    }
    crate::printf!("{}", crate::util::HexDump(frame));
}
