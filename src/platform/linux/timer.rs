//! Linux timer subsystem.
//!
//! A single periodic POSIX timer (CLOCK_REALTIME, 1-millisecond interval)
//! delivers SIGALRM to the intr dispatcher; the ISR walks the table of
//! registered entries and fires the ones whose interval has elapsed.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ptr;
use core::time::Duration;

use spin::Mutex;

use crate::platform::linux::intr;
use crate::time;

pub type TimerFn = Box<dyn Fn() + Send + Sync>;
type TimerArc = Arc<dyn Fn() + Send + Sync>;

const TIMER_IRQ: intr::IrqNumber = libc::SIGALRM as intr::IrqNumber;

struct TimerEntry {
    interval: Duration,
    last: Duration,
    handler: TimerArc,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct TimerId(libc::timer_t);

// SAFETY: timer_t is an opaque kernel handle; sending it across threads is
// safe because the kernel performs its own locking.
unsafe impl Send for TimerId {}

static TIMERS: Mutex<Vec<TimerEntry>> = Mutex::new(Vec::new());
static TIMER_ID: Mutex<Option<TimerId>> = Mutex::new(None);

pub fn register(interval: Duration, handler: TimerFn) -> Result<(), ()> {
    let mut timers = TIMERS.lock();
    timers.push(TimerEntry {
        interval,
        last: time::now(),
        handler: Arc::from(handler),
    });
    crate::infof!("registered: interval={:?}", interval);
    Ok(())
}

fn isr(_irq: intr::IrqNumber) {
    let now = time::now();
    let expired: Vec<TimerArc> = {
        let mut timers = TIMERS.lock();
        let mut e = Vec::new();
        for entry in timers.iter_mut() {
            if now.saturating_sub(entry.last) >= entry.interval {
                entry.last = now;
                e.push(entry.handler.clone());
            }
        }
        e
    };
    for h in expired {
        h();
    }
}

pub fn init() -> Result<(), ()> {
    intr::register(TIMER_IRQ, Box::new(isr), intr::FLAG_QUIET, "timer")?;

    let mut sev: libc::sigevent = unsafe { core::mem::zeroed() };
    sev.sigev_notify = libc::SIGEV_SIGNAL;
    sev.sigev_signo = libc::SIGALRM;

    let mut timerid: MaybeUninit<libc::timer_t> = MaybeUninit::uninit();
    let ret =
        unsafe { libc::timer_create(libc::CLOCK_REALTIME, &mut sev, timerid.as_mut_ptr()) };
    if ret != 0 {
        crate::errorf!("timer_create failed: {}", std::io::Error::last_os_error());
        return Err(());
    }
    let timerid = unsafe { timerid.assume_init() };
    *TIMER_ID.lock() = Some(TimerId(timerid));
    Ok(())
}

pub fn run() -> Result<(), ()> {
    let timerid = match *TIMER_ID.lock() {
        Some(TimerId(t)) => t,
        None => {
            crate::errorf!("not initialized");
            return Err(());
        }
    };
    let its = libc::itimerspec {
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    let ret = unsafe { libc::timer_settime(timerid, 0, &its, ptr::null_mut()) };
    if ret != 0 {
        crate::errorf!("timer_settime failed: {}", std::io::Error::last_os_error());
        return Err(());
    }
    Ok(())
}

pub fn shutdown() {
    if let Some(TimerId(timerid)) = TIMER_ID.lock().take() {
        unsafe { libc::timer_delete(timerid) };
    }
}
