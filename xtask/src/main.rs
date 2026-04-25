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
        /// Toggle IP forwarding (sysctl net.ipv4.ip_forward).
        cmd forward {
            /// "on" to enable, "off" to disable.
            required state: String
        }
        /// Toggle NAT and FORWARD-chain iptables rules for the TAP network.
        cmd nat {
            /// "on" to enable, "off" to disable.
            required state: String
            /// TAP device name (default: tap0).
            optional tap: String
            /// Outbound interface for NAT (default: auto-detected from default route).
            optional out: String
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
        XtaskCmd::Forward(args) => match parse_state(&args.state) {
            Some(on) => forward(on),
            None => ExitCode::FAILURE,
        },
        XtaskCmd::Nat(args) => {
            let on = match parse_state(&args.state) {
                Some(b) => b,
                None => return ExitCode::FAILURE,
            };
            let tap = args.tap.unwrap_or_else(|| DEFAULT_TAPDEV.to_string());
            let out = match resolve_outbound(args.out) {
                Some(s) => s,
                None => return ExitCode::FAILURE,
            };
            nat(&tap, &out, on)
        }
    }
}

fn parse_state(s: &str) -> Option<bool> {
    match s {
        "on" => Some(true),
        "off" => Some(false),
        other => {
            eprintln!("invalid state: {} (expected on|off)", other);
            None
        }
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

fn forward(on: bool) -> ExitCode {
    let target: u32 = if on { 1 } else { 0 };
    if read_ip_forward() == Some(target) {
        return ExitCode::SUCCESS;
    }
    let arg = format!("net.ipv4.ip_forward={}", target);
    eprintln!("sudo sysctl -w {}", arg);
    if run("sudo", &["sysctl", "-w", &arg]).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

struct Rule<'a> {
    table: &'a str,
    chain: &'a str,
    spec: Vec<&'a str>,
}

fn iptables_args<'a>(rule: &'a Rule, action: &'a str) -> Vec<&'a str> {
    let mut v = vec!["iptables", "-t", rule.table, action, rule.chain];
    v.extend(rule.spec.iter().copied());
    v
}

fn iptables_exists(rule: &Rule) -> bool {
    let args = iptables_args(rule, "-C");
    Command::new("sudo")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn nat(tap: &str, out: &str, on: bool) -> ExitCode {
    let net = match cidr_network(DEFAULT_TAPADDR) {
        Some(n) => n,
        None => {
            eprintln!("invalid DEFAULT_TAPADDR: {}", DEFAULT_TAPADDR);
            return ExitCode::FAILURE;
        }
    };
    let rules = [
        Rule {
            table: "filter",
            chain: "FORWARD",
            spec: vec!["-o", tap, "-j", "ACCEPT"],
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            spec: vec!["-i", tap, "-j", "ACCEPT"],
        },
        Rule {
            table: "nat",
            chain: "POSTROUTING",
            spec: vec!["-s", &net, "-o", out, "-j", "MASQUERADE"],
        },
    ];
    for rule in &rules {
        let exists = iptables_exists(rule);
        let action = if on && !exists {
            "-A"
        } else if !on && exists {
            "-D"
        } else {
            continue;
        };
        let args = iptables_args(rule, action);
        eprintln!("sudo {}", args.join(" "));
        if run("sudo", &args).is_err() {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn resolve_outbound(arg: Option<String>) -> Option<String> {
    if let Some(s) = arg {
        return Some(s);
    }
    match detect_outbound_iface() {
        Some(s) => Some(s),
        None => {
            eprintln!("could not detect outbound interface; specify with [out]");
            None
        }
    }
}

fn read_ip_forward() -> Option<u32> {
    let output = Command::new("sysctl")
        .args(["-n", "net.ipv4.ip_forward"])
        .output()
        .ok()?;
    let s = String::from_utf8(output.stdout).ok()?;
    s.trim().parse().ok()
}

fn detect_outbound_iface() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let s = String::from_utf8(output.stdout).ok()?;
    let parts: Vec<&str> = s.split_whitespace().collect();
    let i = parts.iter().position(|&p| p == "dev")?;
    parts.get(i + 1).map(|s| s.to_string())
}

fn cidr_network(cidr: &str) -> Option<String> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let octets: Vec<u8> = addr_str
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if octets.len() != 4 {
        return None;
    }
    let addr_u32 = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let net = addr_u32 & mask;
    Some(format!(
        "{}.{}.{}.{}/{}",
        (net >> 24) & 0xff,
        (net >> 16) & 0xff,
        (net >> 8) & 0xff,
        net & 0xff,
        prefix,
    ))
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
