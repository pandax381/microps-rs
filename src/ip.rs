//! IP protocol.

use crate::device::Device;
use crate::net;

fn input(data: &[u8], dev: &Device) {
    crate::debugf!("dev={}, len={}", dev.name, data.len());
    crate::printf!("{}", crate::util::HexDump(data));
}

pub fn init() -> Result<(), ()> {
    net::register_protocol(net::PROTOCOL_TYPE_IP, input)?;
    Ok(())
}
