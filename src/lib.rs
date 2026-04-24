#![no_std]

extern crate alloc;

#[cfg(feature = "linux")]
extern crate std;

pub mod log;
pub mod net;
pub mod platform;
pub mod time;
pub mod util;
