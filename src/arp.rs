//! ARP protocol.

use crate::device::{Device, FAMILY_IP};
use crate::ether::{EtherAddr, ETHER_ADDR_LEN, ETHER_TYPE_ARP, ETHER_TYPE_IP};
use crate::ip::{IpAddr, IpIface, IP_ADDR_LEN};
use crate::net;

pub const ARP_HRD_ETHER: u16 = 0x0001;
pub const ARP_PRO_IP: u16 = ETHER_TYPE_IP;

pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const ARP_HDR_SIZE: usize = 8;
pub const ARP_ETHER_IP_SIZE: usize = ARP_HDR_SIZE + (ETHER_ADDR_LEN + IP_ADDR_LEN) * 2;

pub struct ArpHdr<'a> {
    data: &'a [u8],
}

impl<'a> ArpHdr<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ARP_HDR_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn hrd(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn pro(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn hln(&self) -> u8 {
        self.data[4]
    }

    pub fn pln(&self) -> u8 {
        self.data[5]
    }

    pub fn op(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }
}

pub struct ArpEtherIP<'a> {
    data: &'a [u8],
}

impl<'a> ArpEtherIP<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ARP_ETHER_IP_SIZE {
            return None;
        }
        Some(Self { data })
    }

    pub fn hdr(&self) -> ArpHdr<'_> {
        ArpHdr { data: self.data }
    }

    pub fn sha(&self) -> EtherAddr {
        let mut a = [0u8; ETHER_ADDR_LEN];
        a.copy_from_slice(&self.data[8..14]);
        EtherAddr(a)
    }

    pub fn spa(&self) -> IpAddr {
        let mut a = [0u8; IP_ADDR_LEN];
        a.copy_from_slice(&self.data[14..18]);
        IpAddr(a)
    }

    pub fn tha(&self) -> EtherAddr {
        let mut a = [0u8; ETHER_ADDR_LEN];
        a.copy_from_slice(&self.data[18..24]);
        EtherAddr(a)
    }

    pub fn tpa(&self) -> IpAddr {
        let mut a = [0u8; IP_ADDR_LEN];
        a.copy_from_slice(&self.data[24..28]);
        IpAddr(a)
    }
}

fn op_name(op: u16) -> &'static str {
    match op {
        ARP_OP_REQUEST => "Request",
        ARP_OP_REPLY => "Reply",
        _ => "Unknown",
    }
}

fn print(data: &[u8]) {
    if let Some(arp) = ArpEtherIP::new(data) {
        let hdr = arp.hdr();
        crate::printf!("        hrd: 0x{:04x}", hdr.hrd());
        crate::printf!("        pro: 0x{:04x}", hdr.pro());
        crate::printf!("        hln: {}", hdr.hln());
        crate::printf!("        pln: {}", hdr.pln());
        crate::printf!("         op: {} ({})", hdr.op(), op_name(hdr.op()));
        crate::printf!("        sha: {}", arp.sha());
        crate::printf!("        spa: {}", arp.spa());
        crate::printf!("        tha: {}", arp.tha());
        crate::printf!("        tpa: {}", arp.tpa());
    }
    crate::printf!("{}", crate::util::HexDump(data));
}

fn reply(dev: &Device, tha: EtherAddr, tpa: IpAddr, src: IpAddr) -> Result<(), ()> {
    let mut buf = [0u8; ARP_ETHER_IP_SIZE];
    buf[0..2].copy_from_slice(&ARP_HRD_ETHER.to_be_bytes());
    buf[2..4].copy_from_slice(&ARP_PRO_IP.to_be_bytes());
    buf[4] = ETHER_ADDR_LEN as u8;
    buf[5] = IP_ADDR_LEN as u8;
    buf[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());

    let my_addr = *dev.addr.lock();
    buf[8..14].copy_from_slice(&my_addr[..ETHER_ADDR_LEN]);
    buf[14..18].copy_from_slice(&src.0);
    buf[18..24].copy_from_slice(&tha.0);
    buf[24..28].copy_from_slice(&tpa.0);

    crate::debugf!("dev={}, len={}", dev.name, ARP_ETHER_IP_SIZE);
    print(&buf);

    dev.output(ETHER_TYPE_ARP, &buf, &tha.0)
}

fn input(data: &[u8], dev: &Device) {
    crate::debugf!("dev={}, len={}", dev.name, data.len());

    let hdr = match ArpHdr::new(data) {
        Some(h) => h,
        None => {
            crate::errorf!("too short, dev={}", dev.name);
            return;
        }
    };

    if hdr.hrd() != ARP_HRD_ETHER || hdr.hln() != ETHER_ADDR_LEN as u8 {
        crate::errorf!(
            "unsupported hardware, hrd=0x{:04x}, hln={}",
            hdr.hrd(),
            hdr.hln()
        );
        return;
    }
    if hdr.pro() != ARP_PRO_IP || hdr.pln() != IP_ADDR_LEN as u8 {
        crate::errorf!(
            "unsupported protocol, pro=0x{:04x}, pln={}",
            hdr.pro(),
            hdr.pln()
        );
        return;
    }

    let arp = match ArpEtherIP::new(data) {
        Some(a) => a,
        None => {
            crate::errorf!("too short for ether/ip, dev={}", dev.name);
            return;
        }
    };

    print(data);

    let iface_any = match dev.get_iface(FAMILY_IP) {
        Some(i) => i,
        None => {
            crate::debugf!("no IP iface, dev={}", dev.name);
            return;
        }
    };
    let iface = match iface_any.as_any().downcast_ref::<IpIface>() {
        Some(i) => i,
        None => return,
    };

    if arp.tpa() == iface.unicast() {
        if hdr.op() == ARP_OP_REQUEST {
            let _ = reply(dev, arp.sha(), arp.spa(), iface.unicast());
        }
    }
}

pub fn init() -> Result<(), ()> {
    net::register_protocol(ETHER_TYPE_ARP, input)?;
    Ok(())
}
