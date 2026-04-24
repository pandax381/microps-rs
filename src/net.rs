//! Network stack lifecycle.

use crate::device::Device;

pub fn init() -> Result<(), ()> {
    crate::infof!("initialize...");
    crate::platform::init()?;
    crate::infof!("success");
    Ok(())
}

pub fn run() -> Result<(), ()> {
    crate::infof!("startup...");
    crate::platform::run()?;
    crate::device::try_foreach(|dev| dev.open())?;
    crate::infof!("success");
    Ok(())
}

pub fn shutdown() {
    crate::infof!("shutting down...");
    crate::device::foreach(|dev| {
        let _ = dev.close();
    });
    crate::platform::shutdown();
    crate::infof!("success");
}

pub fn input_handler(ty: u16, data: &[u8], dev: &Device) -> Result<(), ()> {
    crate::debugf!("dev={}, type=0x{:04x}, len={}", dev.name, ty, data.len());
    crate::printf!("{}", crate::util::HexDump(data));
    Ok(())
}
