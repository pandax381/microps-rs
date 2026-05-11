//! TCP protocol.

use crate::ip::{self, IpAddr, IpEndp, IpHdr, IpIface, IP_PROTOCOL_TCP};
use crate::util;

pub const TCP_HDR_SIZE: usize = 20;
const TCP_PSEUDO_HDR_SIZE: usize = 12;

pub const TCP_FLG_FIN: u8 = 0x01;
pub const TCP_FLG_SYN: u8 = 0x02;
pub const TCP_FLG_RST: u8 = 0x04;
pub const TCP_FLG_PSH: u8 = 0x08;
pub const TCP_FLG_ACK: u8 = 0x10;
pub const TCP_FLG_URG: u8 = 0x20;

fn flag_isset(flg: u8, mask: u8) -> bool {
    (flg & 0x3f) & mask != 0
}

fn build_pseudo_header(src: IpAddr, dst: IpAddr, tcp_len: u16) -> [u8; TCP_PSEUDO_HDR_SIZE] {
    let mut buf = [0u8; TCP_PSEUDO_HDR_SIZE];
    buf[0..4].copy_from_slice(&src.0);
    buf[4..8].copy_from_slice(&dst.0);
    buf[9] = IP_PROTOCOL_TCP;
    buf[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    buf
}

pub struct TcpHdr<'a> {
    data: &'a [u8],
}

impl<'a> TcpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < TCP_HDR_SIZE {
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

    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn ack(&self) -> u32 {
        u32::from_be_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    pub fn off(&self) -> u8 {
        self.data[12]
    }

    pub fn hlen(&self) -> usize {
        ((self.off() >> 4) as usize) * 4
    }

    pub fn flg(&self) -> u8 {
        self.data[13]
    }

    pub fn wnd(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    pub fn sum(&self) -> u16 {
        u16::from_be_bytes([self.data[16], self.data[17]])
    }

    pub fn up(&self) -> u16 {
        u16::from_be_bytes([self.data[18], self.data[19]])
    }
}

fn flag_char(flg: u8, mask: u8, c: char) -> char {
    if flag_isset(flg, mask) { c } else { '-' }
}

struct FlagStr(u8);

impl core::fmt::Display for FlagStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let flg = self.0;
        write!(
            f,
            "--{}{}{}{}{}{}",
            flag_char(flg, TCP_FLG_URG, 'U'),
            flag_char(flg, TCP_FLG_ACK, 'A'),
            flag_char(flg, TCP_FLG_PSH, 'P'),
            flag_char(flg, TCP_FLG_RST, 'R'),
            flag_char(flg, TCP_FLG_SYN, 'S'),
            flag_char(flg, TCP_FLG_FIN, 'F'),
        )
    }
}

fn option_name(kind: u8) -> &'static str {
    match kind {
        0 => "End of Option List (EOL)",
        1 => "No-Operation (NOP)",
        2 => "Maximum Segment Size (MSS)",
        3 => "Window Scale",
        4 => "SACK Permitted",
        5 => "SACK",
        8 => "Timestamps",
        _ => "Unknown",
    }
}

fn print(data: &[u8]) {
    let Some(hdr) = TcpHdr::new(data) else { return };
    let hlen = hdr.hlen();
    crate::printf!("        src: {}", hdr.src());
    crate::printf!("        dst: {}", hdr.dst());
    crate::printf!("        seq: {}", hdr.seq());
    crate::printf!("        ack: {}", hdr.ack());
    crate::printf!(
        "        off: 0x{:02x} ({}) (options: {}, payload: {})",
        hdr.off(),
        hlen,
        hlen - TCP_HDR_SIZE,
        data.len() - hlen,
    );
    crate::printf!("        flg: 0x{:02x} ({})", hdr.flg(), FlagStr(hdr.flg()));
    crate::printf!("        wnd: {}", hdr.wnd());
    crate::printf!("        sum: 0x{:04x}", hdr.sum());
    crate::printf!("         up: {}", hdr.up());

    let mut i = 0;
    let mut pos = TCP_HDR_SIZE;
    while pos < hlen {
        let kind = data[pos];
        if kind == 0 {
            crate::printf!("     opt[{}]: kind={} ({})", i, kind, option_name(kind));
            break;
        }
        if kind == 1 {
            crate::printf!("     opt[{}]: kind={} ({})", i, kind, option_name(kind));
            pos += 1;
        } else {
            if pos + 1 >= hlen {
                break;
            }
            let olen = data[pos + 1] as usize;
            crate::printf!(
                "     opt[{}]: kind={} ({}), len={}",
                i,
                kind,
                option_name(kind),
                olen,
            );
            if olen == 0 {
                break;
            }
            pos += olen;
        }
        i += 1;
    }
    crate::printf!("{}", util::HexDump(data));
}

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    if data.len() < TCP_HDR_SIZE {
        crate::errorf!("too short, len={}", data.len());
        return;
    }
    let Some(tcp) = TcpHdr::new(data) else { return };

    let pseudo = build_pseudo_header(hdr.src(), hdr.dst(), data.len() as u16);
    let init = !util::cksum16(&pseudo, 0) as u32;
    if util::cksum16(data, init) != 0 {
        crate::errorf!("checksum error, sum=0x{:04x}", tcp.sum());
        return;
    }

    let src = IpEndp::new(hdr.src(), tcp.src());
    let dst = IpEndp::new(hdr.dst(), tcp.dst());
    if hdr.src() == IpAddr::BROADCAST
        || hdr.src() == iface.broadcast()
        || hdr.dst() == IpAddr::BROADCAST
        || hdr.dst() == iface.broadcast()
    {
        crate::errorf!("only supports unicast, src={}, dst={}", src, dst);
        return;
    }

    crate::debugf!(
        "{} => {}, len={}, dev={}",
        src,
        dst,
        data.len(),
        iface.dev().name,
    );
    print(data);
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_TCP, input)?;
    Ok(())
}
