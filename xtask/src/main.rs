use std::env;
use std::process::{Command, ExitCode, Stdio};

const DEFAULT_TAPDEV: &str = "tap0";
const DEFAULT_TAPADDR: &str = "192.0.2.1/24";

xflags::xflags! {
    /// Project task runner.
    cmd xtask {
        /// Manage the TAP device.
        cmd tap {
            /// Create the TAP device.
            cmd create {
                /// TAP device name (default: tap0).
                optional dev: String
                /// TAP IP address with prefix length (default: 192.0.2.1/24).
                optional addr: String
            }
            /// Delete the TAP device.
            cmd delete {
                /// TAP device name (default: tap0).
                optional dev: String
            }
        }
    }
}

fn main() -> ExitCode {
    let flags = Xtask::from_env_or_exit();
    match flags.subcommand {
        XtaskCmd::Tap(args) => match args.subcommand {
            TapCmd::Create(c) => {
                let dev = c.dev.as_deref().unwrap_or(DEFAULT_TAPDEV);
                let addr = c.addr.as_deref().unwrap_or(DEFAULT_TAPADDR);
                tap_create(dev, addr)
            }
            TapCmd::Delete(d) => {
                let dev = d.dev.as_deref().unwrap_or(DEFAULT_TAPDEV);
                tap_delete(dev)
            }
        },
    }
}

fn tap_create(dev: &str, addr: &str) -> ExitCode {
    if iface_exists(dev) {
        return ExitCode::SUCCESS;
    }
    let user = env::var("USER").unwrap_or_default();
    let sysctl = format!("net.ipv6.conf.{}.disable_ipv6=1", dev);
    let cmds: Vec<Vec<&str>> = vec![
        vec!["ip", "tuntap", "add", "mode", "tap", "user", &user, "name", dev],
        vec!["sysctl", "-w", &sysctl],
        vec!["ip", "addr", "add", addr, "dev", dev],
        vec!["ip", "link", "set", dev, "up"],
    ];
    for cmd in &cmds {
        eprintln!("sudo {}", cmd.join(" "));
        if run("sudo", cmd).is_err() {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn tap_delete(dev: &str) -> ExitCode {
    if !iface_exists(dev) {
        return ExitCode::SUCCESS;
    }
    let cmd: Vec<&str> = vec!["ip", "tuntap", "del", "mode", "tap", "name", dev];
    eprintln!("sudo {}", cmd.join(" "));
    if run("sudo", &cmd).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn iface_exists(dev: &str) -> bool {
    Command::new("ip")
        .args(["addr", "show", dev])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str]) -> Result<(), ()> {
    let status = Command::new(program).args(args).status().map_err(|e| {
        eprintln!("failed to spawn {}: {}", program, e);
    })?;
    if !status.success() {
        eprintln!("{} {:?} exited with {}", program, args, status);
        return Err(());
    }
    Ok(())
}
