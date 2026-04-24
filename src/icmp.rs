//! ICMP protocol.

use crate::ip::{self, IpHdr, IpIface, IP_PROTOCOL_ICMP};

fn input(hdr: &IpHdr<'_>, data: &[u8], iface: &IpIface) {
    crate::debugf!(
        "{} => {}, dev={}, len={}",
        hdr.src(),
        hdr.dst(),
        iface.dev().name,
        data.len()
    );
    crate::printf!("{}", crate::util::HexDump(data));
}

pub fn init() -> Result<(), ()> {
    ip::register_protocol(IP_PROTOCOL_ICMP, input)?;
    Ok(())
}
