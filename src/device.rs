//! Network device abstraction.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use spin::Mutex;

pub const ADDR_LEN: usize = 16;

pub const TYPE_DUMMY: u16 = 0x0000;
pub const TYPE_LOOPBACK: u16 = 0x0001;
pub const TYPE_ETHERNET: u16 = 0x0002;

pub const FLAG_UP: u16 = 0x0001;
pub const FLAG_LOOPBACK: u16 = 0x0010;
pub const FLAG_BROADCAST: u16 = 0x0020;
pub const FLAG_P2P: u16 = 0x0040;
pub const FLAG_NEED_ARP: u16 = 0x0100;

pub struct Device {
    pub index: usize,
    pub name: String,
    pub ty: u16,
    pub mtu: u16,
    pub hlen: u16,
    pub alen: u16,
    pub addr: [u8; ADDR_LEN],
    pub peer: [u8; ADDR_LEN],
    pub broadcast: [u8; ADDR_LEN],
    flags: AtomicU16,
}

impl Device {
    pub fn new(ty: u16, mtu: u16, flags: u16) -> Self {
        Self {
            index: 0,
            name: String::new(),
            ty,
            mtu,
            hlen: 0,
            alen: 0,
            addr: [0; ADDR_LEN],
            peer: [0; ADDR_LEN],
            broadcast: [0; ADDR_LEN],
            flags: AtomicU16::new(flags),
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags.load(Ordering::Acquire)
    }

    pub fn is_up(&self) -> bool {
        self.flags() & FLAG_UP != 0
    }

    pub fn state(&self) -> &'static str {
        if self.is_up() {
            "UP"
        } else {
            "DOWN"
        }
    }

    pub fn open(&self) -> Result<(), ()> {
        if self.is_up() {
            crate::errorf!("already opened, dev={}", self.name);
            return Err(());
        }
        self.flags.fetch_or(FLAG_UP, Ordering::AcqRel);
        crate::infof!("dev={}, state={}", self.name, self.state());
        Ok(())
    }

    pub fn close(&self) -> Result<(), ()> {
        if !self.is_up() {
            crate::errorf!("not opened, dev={}", self.name);
            return Err(());
        }
        self.flags.fetch_and(!FLAG_UP, Ordering::AcqRel);
        crate::infof!("dev={}, state={}", self.name, self.state());
        Ok(())
    }

    pub fn output(&self, ty: u16, data: &[u8], _dst: &[u8]) -> Result<(), ()> {
        if !self.is_up() {
            crate::errorf!("not opened, dev={}", self.name);
            return Err(());
        }
        if data.len() as u16 > self.mtu {
            crate::errorf!(
                "too long, dev={}, mtu={}, len={}",
                self.name,
                self.mtu,
                data.len()
            );
            return Err(());
        }
        crate::debugf!("dev={}, type=0x{:04x}, len={}", self.name, ty, data.len());
        crate::printf!("{}", crate::util::HexDump(data));
        Ok(())
    }
}

static DEVICES: Mutex<Vec<Arc<Device>>> = Mutex::new(Vec::new());

pub fn register(mut dev: Device) -> Arc<Device> {
    let mut devices = DEVICES.lock();
    dev.index = devices.len();
    dev.name = format!("net{}", dev.index);
    crate::infof!("registered dev={}, type=0x{:04x}", dev.name, dev.ty);
    let arc = Arc::new(dev);
    devices.push(arc.clone());
    arc
}

pub fn foreach<F>(mut f: F)
where
    F: FnMut(&Device),
{
    for dev in DEVICES.lock().iter() {
        f(dev);
    }
}

pub fn try_foreach<F>(mut f: F) -> Result<(), ()>
where
    F: FnMut(&Device) -> Result<(), ()>,
{
    for dev in DEVICES.lock().iter() {
        f(dev)?;
    }
    Ok(())
}
