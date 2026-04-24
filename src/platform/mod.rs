//! Platform abstraction.
//!
//! Selects the concrete platform at build time via Cargo features and
//! re-exports its symbols so the rest of the crate can call
//! `crate::platform::init()` etc. without knowing which one it is.

#[cfg(not(any(feature = "linux")))]
compile_error!("microps requires a platform feature (e.g., `linux`)");

#[cfg(feature = "linux")]
mod linux;
#[cfg(feature = "linux")]
pub use linux::*;
