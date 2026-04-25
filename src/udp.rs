//! UDP protocol.

use crate::ip::{self, IpAddr, IpEndp, IpHdr, IpIface, IP_PROTOCOL_UDP};
use crate::util;

pub const UDP_HDR_SIZE: usize = 8;
const UDP_PSEUDO_HDR_SIZE: usize = 12;

fn build_pseudo_header(src: IpAddr, dst: IpAddr, udp_len: u16) -> [u8; UDP_PSEUDO_HDR_SIZE] {
    let mut buf = [0u8; UDP_PSEUDO_HDR_SIZE];
    buf[0..4].copy_from_slice(&src.0);
    buf[4..8].copy_from_slice(&dst.0);
    buf[9] = IP_PROTOCOL_UDP;
    buf[10..12].copy_from_slice(&udp_len.to_be_bytes());
    buf
}

pub struct UdpHdr<'a> {
    data: &'a [u8],
}

impl<'a> UdpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < UDP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn src(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn dst(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn len(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }
}

fn print(data: &[u8]) {
    if let Some(hdr) = UdpHdr::new(data) {
        crate::printf!("        src: {}", hdr.src());
        crate::printf!("        dst: {}", hdr.dst());
        crate::printf!("        len: {}", hdr.len());
        crate::printf!("        sum: 0x{:04x}", hdr.sum());
    }
    crate::printf!("{}", crate::util::HexDump(data));
}

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    if data.len() < UDP_HDR_SIZE {
        crate::errorf!("too short, len={}", data.len());
        return;
    }
    let udp = match UdpHdr::new(data) {
        Some(u) => u,
        None => return,
    };
    if (udp.len() as usize) != data.len() {
        crate::errorf!(
            "length mismatch, header={}, actual={}",
            udp.len(),
            data.len()
        );
        return;
    }
    if udp.sum() != 0 {
        let pseudo = build_pseudo_header(hdr.src(), hdr.dst(), data.len() as u16);
        let init = !util::cksum16(&pseudo, 0) as u32;
        if util::cksum16(data, init) != 0 {
            crate::errorf!("checksum error, sum=0x{:04x}", udp.sum());
            return;
        }
    }
    let src = IpEndp::new(hdr.src(), udp.src());
    let dst = IpEndp::new(hdr.dst(), udp.dst());
    crate::debugf!(
        "{} => {}, dev={}, len={}",
        src,
        dst,
        iface.dev().name,
        data.len()
    );
    print(data);
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_UDP, input)?;
    Ok(())
}
