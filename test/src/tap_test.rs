use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::ExitCode;

use microps::ether;
use microps::{errorf, infof};

const CLONE_DEVICE: &str = "/dev/net/tun";

const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let tap_name = match args.get(1) {
        Some(name) => name.as_str(),
        None => {
            errorf!("usage: {} <tap-name>", args[0]);
            return ExitCode::FAILURE;
        }
    };
    let path = CString::new(CLONE_DEVICE).unwrap();
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if raw < 0 {
        errorf!("open: {}", std::io::Error::last_os_error());
        return ExitCode::FAILURE;
    }
    // SAFETY: `raw` is a fresh fd from open(); ownership transfers to OwnedFd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let name_bytes = tap_name.as_bytes();
    if name_bytes.len() >= 16 {
        errorf!("name too long: {}", tap_name);
        return ExitCode::FAILURE;
    }
    let mut ifr = Ifreq {
        name: [0; 16],
        flags: IFF_TAP | IFF_NO_PI,
        _pad: [0; 22],
    };
    ifr.name[..name_bytes.len()].copy_from_slice(name_bytes);
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut ifr as *mut _) } < 0 {
        errorf!("ioctl(TUNSETIFF): {}", std::io::Error::last_os_error());
        return ExitCode::FAILURE;
    }
    infof!("waiting for packets from <{}>...", tap_name);
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            errorf!("read: {}", err);
            break;
        }
        if n == 0 {
            continue;
        }
        infof!("receive {} bytes data", n);
        ether::print(&buf[..n as usize]);
    }
    ExitCode::SUCCESS
}
