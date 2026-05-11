use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use microps::driver::loopback;
use microps::ether::EtherAddr;
use microps::ip::{self, IpAddr};
use microps::platform::driver::ether_tap;
use microps::platform::intr;
use microps::sock::{self, SocketAddr};
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

fn app_main() -> Result<(), ()> {
    let local: SocketAddr = "0.0.0.0:7".parse()?;
    let soc = sock::open(sock::AF_INET, sock::SOCK_STREAM)?;
    if sock::bind(soc, local).is_err() {
        errorf!("sock::bind() failure");
        let _ = sock::close(soc);
        return Err(());
    }
    if sock::listen(soc, 1).is_err() {
        errorf!("sock::listen() failure");
        let _ = sock::close(soc);
        return Err(());
    }
    debugf!("press Ctrl+C to terminate");
    while !TERMINATE.load(Ordering::Relaxed) {
        let (acc, remote) = match sock::accept(soc) {
            Ok(v) => v,
            Err(()) => {
                if TERMINATE.load(Ordering::Relaxed) {
                    warnf!("sock::accept() interrupted");
                    break;
                }
                errorf!("sock::accept() failure");
                break;
            }
        };
        debugf!("connection accepted, remote={}", remote);
        conn_main(acc);
    }
    let _ = sock::close(soc);
    debugf!("terminate");
    Ok(())
}

fn conn_main(soc: sock::SockDesc) {
    let mut buf = [0u8; 128];
    loop {
        let n = match sock::recv(soc, &mut buf) {
            Ok(0) => {
                debugf!("connection closed");
                break;
            }
            Ok(n) => n,
            Err(()) => {
                errorf!("sock::recv() failure");
                break;
            }
        };
        infof!("{} bytes received", n);
        printf!("{}", HexDump(&buf[..n]));
        if sock::send(soc, &buf[..n]).is_err() {
            errorf!("sock::send() failure");
            break;
        }
    }
    let _ = sock::close(soc);
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
