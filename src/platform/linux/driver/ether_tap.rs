//! Linux Ethernet TAP device driver.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use std::ffi::CString;
use std::io;

use spin::Mutex;

use crate::device::{self, Device, Ops, FLAG_BROADCAST, FLAG_NEED_ARP, TYPE_ETHERNET};
use crate::ether::{
    self, EtherAddr, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN, ETHER_FRAME_SIZE_MAX, ETHER_HDR_SIZE,
    ETHER_PAYLOAD_SIZE_MAX, ETHER_PAYLOAD_SIZE_MIN,
};
use crate::net;
use crate::platform::linux::intr;

const CLONE_DEVICE: &str = "/dev/net/tun";
const IFNAMSIZ: usize = 16;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const F_SETSIG: libc::c_int = 10;

#[repr(C)]
#[derive(Default)]
struct IfreqFlags {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

#[repr(C)]
#[derive(Default)]
struct IfreqHwaddr {
    ifr_name: [u8; IFNAMSIZ],
    sa_family: u16,
    sa_data: [u8; 14],
    _pad: [u8; 8],
}

struct EtherTap {
    name: String,
    configured_addr: Option<EtherAddr>,
    fd: Mutex<libc::c_int>,
    irq: intr::IrqNumber,
}

struct EtherTapOps {
    inner: Arc<EtherTap>,
}

impl Ops for EtherTapOps {
    fn open(&self, dev: &Device) -> Result<(), ()> {
        open(&self.inner, dev)
    }

    fn close(&self, _dev: &Device) -> Result<(), ()> {
        close(&self.inner)
    }

    fn transmit(&self, dev: &Device, ty: u16, data: &[u8], dst: &[u8]) -> Result<(), ()> {
        transmit(&self.inner, dev, ty, data, dst)
    }
}

fn query_mac(name: &str) -> Result<EtherAddr, ()> {
    let soc = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if soc == -1 {
        crate::errorf!("socket: {}", io::Error::last_os_error());
        return Err(());
    }

    let mut ifr = IfreqHwaddr::default();
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ret = unsafe { libc::ioctl(soc, libc::SIOCGIFHWADDR, &mut ifr as *mut IfreqHwaddr) };
    let err = io::Error::last_os_error();
    unsafe { libc::close(soc) };

    if ret == -1 {
        crate::errorf!("ioctl(SIOCGIFHWADDR): {}, dev={}", err, name);
        return Err(());
    }

    let mut mac = [0u8; ETHER_ADDR_LEN];
    mac.copy_from_slice(&ifr.sa_data[..ETHER_ADDR_LEN]);
    Ok(EtherAddr(mac))
}

fn open(tap: &EtherTap, dev: &Device) -> Result<(), ()> {
    let path = CString::new(CLONE_DEVICE).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd == -1 {
        crate::errorf!("open: {}, dev={}", io::Error::last_os_error(), tap.name);
        return Err(());
    }

    let mut ifr = IfreqFlags::default();
    let name_bytes = tap.name.as_bytes();
    let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut IfreqFlags) } == -1 {
        crate::errorf!(
            "ioctl(TUNSETIFF): {}, dev={}",
            io::Error::last_os_error(),
            tap.name
        );
        unsafe { libc::close(fd) };
        return Err(());
    }

    let mac = match tap.configured_addr {
        Some(a) => a,
        None => match query_mac(&tap.name) {
            Ok(a) => a,
            Err(()) => {
                unsafe { libc::close(fd) };
                return Err(());
            }
        },
    };
    dev.addr.lock()[..ETHER_ADDR_LEN].copy_from_slice(&mac.0);

    if unsafe { libc::fcntl(fd, libc::F_SETOWN, libc::getpid()) } == -1 {
        crate::errorf!(
            "fcntl(F_SETOWN): {}, dev={}",
            io::Error::last_os_error(),
            tap.name
        );
        unsafe { libc::close(fd) };
        return Err(());
    }

    let val = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if val == -1 {
        crate::errorf!(
            "fcntl(F_GETFL): {}, dev={}",
            io::Error::last_os_error(),
            tap.name
        );
        unsafe { libc::close(fd) };
        return Err(());
    }

    if unsafe { libc::fcntl(fd, libc::F_SETFL, val | libc::O_ASYNC | libc::O_NONBLOCK) } == -1 {
        crate::errorf!(
            "fcntl(F_SETFL): {}, dev={}",
            io::Error::last_os_error(),
            tap.name
        );
        unsafe { libc::close(fd) };
        return Err(());
    }

    if unsafe { libc::fcntl(fd, F_SETSIG, tap.irq as libc::c_int) } == -1 {
        crate::errorf!(
            "fcntl(F_SETSIG): {}, dev={}",
            io::Error::last_os_error(),
            tap.name
        );
        unsafe { libc::close(fd) };
        return Err(());
    }

    *tap.fd.lock() = fd;
    crate::infof!(
        "dev={}, fd={}, irq={}, addr={}",
        tap.name,
        fd,
        tap.irq,
        mac
    );
    Ok(())
}

fn close(tap: &EtherTap) -> Result<(), ()> {
    let mut fd_guard = tap.fd.lock();
    let fd = *fd_guard;
    if fd != -1 {
        unsafe { libc::close(fd) };
        *fd_guard = -1;
    }
    Ok(())
}

fn transmit(tap: &EtherTap, dev: &Device, ty: u16, data: &[u8], dst: &[u8]) -> Result<(), ()> {
    if dst.len() < ETHER_ADDR_LEN {
        crate::errorf!("dst too short, dev={}", tap.name);
        return Err(());
    }
    if data.len() > ETHER_PAYLOAD_SIZE_MAX {
        crate::errorf!("payload too long, dev={}, len={}", tap.name, data.len());
        return Err(());
    }
    let src = *dev.addr.lock();

    let mut frame = [0u8; ETHER_FRAME_SIZE_MAX];
    frame[..ETHER_ADDR_LEN].copy_from_slice(&dst[..ETHER_ADDR_LEN]);
    frame[ETHER_ADDR_LEN..2 * ETHER_ADDR_LEN].copy_from_slice(&src[..ETHER_ADDR_LEN]);
    frame[2 * ETHER_ADDR_LEN..ETHER_HDR_SIZE].copy_from_slice(&ty.to_be_bytes());
    frame[ETHER_HDR_SIZE..ETHER_HDR_SIZE + data.len()].copy_from_slice(data);

    let payload_len = data.len().max(ETHER_PAYLOAD_SIZE_MIN);
    let total_len = ETHER_HDR_SIZE + payload_len;

    crate::debugf!("dev={}, type=0x{:04x}, len={}", tap.name, ty, total_len);
    ether::print(&frame[..total_len]);

    let fd = *tap.fd.lock();
    if fd == -1 {
        crate::errorf!("device not opened, dev={}", tap.name);
        return Err(());
    }

    let n = unsafe { libc::write(fd, frame.as_ptr() as *const libc::c_void, total_len) };
    if n == -1 {
        crate::errorf!("write: {}, dev={}", io::Error::last_os_error(), tap.name);
        return Err(());
    }
    Ok(())
}

fn input(tap: &EtherTap, dev: &Device, frame: &[u8]) {
    if frame.len() < ETHER_HDR_SIZE {
        crate::errorf!("too short, dev={}", tap.name);
        return;
    }

    let dst = &frame[0..ETHER_ADDR_LEN];
    let my_addr = *dev.addr.lock();
    let is_for_me = dst == &my_addr[..ETHER_ADDR_LEN];
    let is_broadcast = dst == ETHER_ADDR_BROADCAST.0;
    if !is_for_me && !is_broadcast {
        return;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    crate::debugf!(
        "dev={}, type=0x{:04x}, len={}",
        tap.name,
        ethertype,
        frame.len()
    );
    ether::print(frame);

    let payload = &frame[ETHER_HDR_SIZE..];
    let _ = net::input_handler(ethertype, payload, dev);
}

fn isr(tap: &EtherTap, dev: &Device) {
    let fd = *tap.fd.lock();
    if fd == -1 {
        return;
    }

    let mut buf = [0u8; ETHER_FRAME_SIZE_MAX];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == -1 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                break;
            }
            crate::errorf!("read: {}, dev={}", err, tap.name);
            return;
        }
        if n == 0 {
            break;
        }
        input(tap, dev, &buf[..n as usize]);
    }
}

pub fn init(name: &str, addr: Option<EtherAddr>) -> Result<Arc<Device>, ()> {
    let irq = (libc::SIGRTMIN() + 1) as intr::IrqNumber;
    let tap = Arc::new(EtherTap {
        name: String::from(name),
        configured_addr: addr,
        fd: Mutex::new(-1),
        irq,
    });
    let ops = EtherTapOps { inner: tap.clone() };

    let mut dev = Device::new(
        TYPE_ETHERNET,
        ETHER_PAYLOAD_SIZE_MAX as u16,
        FLAG_BROADCAST | FLAG_NEED_ARP,
        Box::new(ops),
    );
    dev.hlen = ETHER_HDR_SIZE as u16;
    dev.alen = ETHER_ADDR_LEN as u16;
    dev.broadcast[..ETHER_ADDR_LEN].copy_from_slice(&ETHER_ADDR_BROADCAST.0);

    let dev_arc = device::register(dev);

    let tap_for_isr = tap.clone();
    let dev_for_isr = dev_arc.clone();
    intr::register(
        irq,
        Box::new(move |_irq| isr(&tap_for_isr, &dev_for_isr)),
        intr::FLAG_SHARED,
        "ether_tap",
    )?;

    Ok(dev_arc)
}
