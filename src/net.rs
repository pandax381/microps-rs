//! Network stack lifecycle and protocol dispatch.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;

use crate::device::Device;

pub const PROTOCOL_TYPE_IP: u16 = 0x0800;
pub const PROTOCOL_TYPE_ARP: u16 = 0x0806;
pub const PROTOCOL_TYPE_IPV6: u16 = 0x86dd;

pub type ProtocolHandler = fn(data: &[u8], dev: &Device);

struct Protocol {
    ty: u16,
    handler: ProtocolHandler,
}

struct InputEntry {
    ty: u16,
    data: Vec<u8>,
    dev: Arc<Device>,
}

static PROTOCOLS: Mutex<Vec<Protocol>> = Mutex::new(Vec::new());
static INPUT_QUEUE: Mutex<VecDeque<InputEntry>> = Mutex::new(VecDeque::new());

pub fn register_protocol(ty: u16, handler: ProtocolHandler) -> Result<(), ()> {
    let mut protocols = PROTOCOLS.lock();
    if protocols.iter().any(|p| p.ty == ty) {
        crate::errorf!("already registered, type=0x{:04x}", ty);
        return Err(());
    }
    protocols.push(Protocol { ty, handler });
    crate::infof!("registered, type=0x{:04x}", ty);
    Ok(())
}

pub fn init() -> Result<(), ()> {
    crate::infof!("initialize...");
    crate::platform::init()?;
    crate::arp::init()?;
    crate::ip::init()?;
    crate::icmp::init()?;
    crate::udp::init()?;
    crate::tcp::init()?;
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
    if !PROTOCOLS.lock().iter().any(|p| p.ty == ty) {
        return Ok(());
    }
    let arc = match crate::device::by_index(dev.index) {
        Some(a) => a,
        None => {
            crate::errorf!("device not registered, index={}", dev.index);
            return Err(());
        }
    };
    INPUT_QUEUE.lock().push_back(InputEntry {
        ty,
        data: data.to_vec(),
        dev: arc,
    });
    crate::platform::softirq::raise();
    Ok(())
}

pub fn softirq_handler() {
    loop {
        let entry = match INPUT_QUEUE.lock().pop_front() {
            Some(e) => e,
            None => break,
        };
        let handler = {
            let protocols = PROTOCOLS.lock();
            protocols
                .iter()
                .find(|p| p.ty == entry.ty)
                .map(|p| p.handler)
        };
        if let Some(handler) = handler {
            handler(&entry.data, entry.dev.as_ref());
        }
    }
}
