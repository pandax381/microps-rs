use std::sync::Arc;

use microps::device::{self, Device, TYPE_DUMMY};

const MTU: u16 = u16::MAX;

pub fn init() -> Arc<Device> {
    let dev = Device::new(TYPE_DUMMY, MTU, 0);
    device::register(dev)
}
