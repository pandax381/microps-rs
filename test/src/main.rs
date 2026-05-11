use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use microps::driver::loopback;
use microps::ether::EtherAddr;
use microps::ip::{self, IpAddr, IpEndp};
use microps::platform::driver::ether_tap;
use microps::platform::intr;
use microps::util::HexDump;
use microps::{debugf, infof, net, printf, tcp};

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

fn app_main() -> Result<(), ()> {
    let local: IpEndp = "0.0.0.0:7".parse()?;
    let desc = tcp::socket()?;
    if tcp::bind(desc, local).is_err() {
        let _ = tcp::close(desc);
        return Err(());
    }
    if tcp::listen(desc, 1).is_err() {
        let _ = tcp::close(desc);
        return Err(());
    }
    let (new_desc, remote) = match tcp::accept(desc) {
        Ok(v) => v,
        Err(()) => return Err(()),
    };
    debugf!("connection from {}, desc={}", remote, new_desc);
    debugf!("press Ctrl+C to terminate");
    let mut buf = [0u8; 128];
    while !TERMINATE.load(Ordering::Relaxed) {
        let n = match tcp::receive(new_desc, &mut buf) {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        infof!("{} bytes data received", n);
        printf!("{}", HexDump(&buf[..n]));
        let _ = tcp::send(new_desc, &buf[..n]);
    }
    let _ = tcp::close(new_desc);
    let _ = tcp::close(desc);
    debugf!("terminate");
    Ok(())
}

fn main() -> ExitCode {
    if setup().is_err() {
        return ExitCode::FAILURE;
    }
    let ret = app_main();
    // Give the FIN handshake a moment to complete before shutting down.
    std::thread::sleep(std::time::Duration::from_secs(1));
    if cleanup().is_err() {
        return ExitCode::FAILURE;
    }
    match ret {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}
