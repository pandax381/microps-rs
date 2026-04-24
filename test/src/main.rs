use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use microps::driver::loopback;
use microps::ip::{self, IpAddr};
use microps::{errorf, infof, net};

mod defs;

use defs::{LOOPBACK_IP_ADDR, LOOPBACK_NETMASK, TEST_DATA};

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
    let dev = loopback::init();
    ip::iface_register(&dev, LOOPBACK_IP_ADDR, LOOPBACK_NETMASK)?;
    net::run()?;
    Ok(())
}

fn cleanup() -> Result<(), ()> {
    net::shutdown();
    Ok(())
}

fn app_main() -> Result<(), ()> {
    infof!("press Ctrl+C to terminate");
    let src: IpAddr = LOOPBACK_IP_ADDR.parse()?;
    let dst = src;
    while !TERMINATE.load(Ordering::Relaxed) {
        if ip::output(1, &TEST_DATA[20..], src, dst).is_err() {
            errorf!("ip::output() failure");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
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
