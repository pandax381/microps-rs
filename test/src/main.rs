use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use microps::driver::loopback;
use microps::ether::EtherAddr;
use microps::ip::{self, IpAddr, IpEndp};
use microps::platform::driver::ether_tap;
use microps::platform::intr;
use microps::udp::{self, RecvError, UdpDesc};
use microps::util::HexDump;
use microps::{debugf, errorf, infof, net, printf, warnf};

mod defs;

use defs::{
    DEFAULT_GATEWAY, ETHER_TAP_HW_ADDR, ETHER_TAP_IP_ADDR, ETHER_TAP_NAME, ETHER_TAP_NETMASK,
    LOOPBACK_IP_ADDR, LOOPBACK_NETMASK,
};

static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signum: libc::c_int) {
    TERMINATE.store(true, Ordering::Relaxed);
    intr::raise(libc::SIGUSR2 as intr::IrqNumber);
}

fn setup() -> Result<(), ()> {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_signal as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, core::ptr::null_mut());
    }
    net::init()?;

    let lo = loopback::init();
    ip::iface_register(&lo, LOOPBACK_IP_ADDR, LOOPBACK_NETMASK)?;

    let mac: EtherAddr = ETHER_TAP_HW_ADDR.parse()?;
    let en = ether_tap::init(ETHER_TAP_NAME, Some(mac))?;
    let en_iface = ip::iface_register(&en, ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK)?;
    let gw: IpAddr = DEFAULT_GATEWAY.parse()?;
    ip::set_default_gateway(&en_iface, gw)?;

    net::run()?;
    Ok(())
}

fn cleanup() -> Result<(), ()> {
    net::shutdown();
    Ok(())
}

fn receiver(desc: UdpDesc) {
    debugf!("running...");
    let mut buf = [0u8; 128];
    while !TERMINATE.load(Ordering::Relaxed) {
        match udp::recvfrom(desc, &mut buf) {
            Ok((remote, n)) => {
                infof!("{} bytes data receive from {}", n, remote);
                printf!("{}", HexDump(&buf[..n]));
            }
            Err(RecvError::Interrupted) => continue,
            Err(RecvError::NotBound) => {
                warnf!("udp::recvfrom() failure");
                break;
            }
        }
    }
    debugf!("terminate");
}

fn app_main() -> Result<(), ()> {
    let desc = udp::open().ok_or(())?;
    let remote: IpEndp = "192.0.2.1:10007".parse()?;

    let handle = thread::spawn(move || receiver(desc));

    debugf!("press Ctrl+C to terminate");
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 128];
    while !TERMINATE.load(Ordering::Relaxed) {
        let Ok(n) = stdin.read(&mut buf) else { break; };
        if n == 0 { break; }
        infof!("{} bytes data send to {}", n, remote);
        printf!("{}", HexDump(&buf[..n]));
        if udp::sendto(desc, &buf[..n], remote).is_err() {
            errorf!("udp::sendto() failure");
            break;
        }
    }

    udp::close(desc)?;
    let _ = handle.join();
    debugf!("terminate");
    Ok(())
}

fn main() -> ExitCode {
    if setup().is_err() {
        return ExitCode::FAILURE;
    }
    let ret = app_main();
    if cleanup().is_err() {
        return ExitCode::FAILURE;
    }
    match ret {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}
