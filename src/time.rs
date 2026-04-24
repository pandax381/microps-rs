//! Monotonic clock.

use core::time::Duration;

pub fn now() -> Duration {
    crate::platform::now()
}
