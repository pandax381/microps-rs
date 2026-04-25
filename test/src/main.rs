use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use microps::driver::loopback;
use microps::ether::EtherAddr;
use microps::ip::{self, IpAddr, IpEndp};
use microps::platform::driver::ether_tap;
use microps::{infof, net, udp};

mod defs;

use defs::{
    DEFAULT_GATEWAY, ETHER_TAP_HW_ADDR, ETHER_TAP_IP_ADDR, ETHER_TAP_NAME, ETHER_TAP_NETMASK,
    LOOPBACK_IP_ADDR, LOOPBACK_NETMASK,
};

static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signum: libc::c_int) {
    TERMINATE.store(true, Ordering::Relaxed);
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
    let desc = udp::open().ok_or(())?;
    udp::bind(desc, IpEndp::new(IpAddr::ANY, 7))?;
    infof!("press Ctrl+C to terminate");
    while !TERMINATE.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }
    udp::close(desc)?;
    infof!("terminate");
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
