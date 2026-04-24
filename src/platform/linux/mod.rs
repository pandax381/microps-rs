//! Linux platform implementation.

use std::eprintln;
use std::time::SystemTime;

pub fn init() -> Result<(), ()> {
    Ok(())
}

pub fn run() -> Result<(), ()> {
    Ok(())
}

pub fn shutdown() {}

pub fn now() -> core::time::Duration {
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    core::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

pub fn log_output(level: char, file: &str, line: u32, function: &str, args: core::fmt::Arguments) {
    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let total_secs = d.as_secs();
            let millis = d.subsec_millis();
            let secs_of_day = total_secs % 86400;
            let hours = secs_of_day / 3600;
            let minutes = (secs_of_day % 3600) / 60;
            let seconds = secs_of_day % 60;
            std::format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
        }
        Err(_) => std::string::String::from("??:??:??.???"),
    };

    let filename = file.rsplit('/').next().unwrap_or(file);
    let module = filename.strip_suffix(".rs").unwrap_or(filename);
    let fn_name = function.rsplit("::").next().unwrap_or(function);

    eprintln!(
        "{} [{}] {}::{}: {} ({}:{})",
        timestamp, level, module, fn_name, args, filename, line
    );
}

pub fn print_output(args: core::fmt::Arguments) {
    eprintln!("{}", args);
}
