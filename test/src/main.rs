use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use microps::device::Device;
use microps::driver::loopback;
use microps::{errorf, infof, net};

mod defs;

use defs::TEST_DATA;

static TERMINATE: AtomicBool = AtomicBool::new(false);
static DEV: OnceLock<Arc<Device>> = OnceLock::new();

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
    DEV.set(dev).ok();
    net::run()?;
    Ok(())
}

fn cleanup() -> Result<(), ()> {
    net::shutdown();
    Ok(())
}

fn app_main() -> Result<(), ()> {
    infof!("press Ctrl+C to terminate");
    let dev = DEV.get().unwrap();
    while !TERMINATE.load(Ordering::Relaxed) {
        if dev.output(0x0800, TEST_DATA, &[]).is_err() {
            errorf!("dev.output() failure");
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
