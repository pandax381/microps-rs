//! Linux interrupt mechanism.
//!
//! Emulates hardware interrupts using POSIX signals + a dedicated pthread,
//! mirroring the design in C microps `platform/linux/intr.c`. Signals are
//! blocked on the main thread (and inherited by all subsequent threads),
//! and a single dispatcher thread receives them via `sigwait`.
//!
//! Note: all IRQs must be registered before `run()`; the kernel-level
//! signal mask is built once at that point.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use std::sync::Barrier;
use std::thread::{self, JoinHandle};

use spin::Mutex;

pub type IrqNumber = u32;
pub type IsrFn = Box<dyn Fn(IrqNumber) + Send + Sync>;
type IsrArc = Arc<dyn Fn(IrqNumber) + Send + Sync>;

pub const FLAG_SHARED: u32 = 0x0001;
pub const FLAG_QUIET: u32 = 0x0002;

struct IrqEntry {
    irq: IrqNumber,
    isr: IsrArc,
    flags: u32,
    name: String,
}

#[repr(transparent)]
struct SigSet(libc::sigset_t);

// SAFETY: sigset_t is an opaque bitmask with no interior references.
unsafe impl Send for SigSet {}

impl SigSet {
    fn empty() -> Self {
        unsafe {
            let mut set: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
            libc::sigemptyset(set.as_mut_ptr());
            Self(set.assume_init())
        }
    }

    fn full() -> Self {
        unsafe {
            let mut set: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
            libc::sigfillset(set.as_mut_ptr());
            Self(set.assume_init())
        }
    }

    fn add(&mut self, signum: libc::c_int) {
        unsafe {
            libc::sigaddset(&mut self.0, signum);
        }
    }

    fn as_ptr(&self) -> *const libc::sigset_t {
        &self.0
    }
}

static IRQS: Mutex<Vec<IrqEntry>> = Mutex::new(Vec::new());
static THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

pub fn init() -> Result<(), ()> {
    Ok(())
}

pub fn register(irq: IrqNumber, isr: IsrFn, flags: u32, name: &str) -> Result<(), ()> {
    crate::debugf!("irq={}, flags={}, name={}", irq, flags, name);
    let mut irqs = IRQS.lock();
    for entry in irqs.iter() {
        if entry.irq == irq {
            let both_shared = (entry.flags & FLAG_SHARED != 0) && (flags & FLAG_SHARED != 0);
            if !both_shared {
                crate::errorf!("conflicts with already registered IRQs, irq={}", irq);
                return Err(());
            }
        }
    }
    let isr_arc: IsrArc = Arc::from(isr);
    irqs.push(IrqEntry {
        irq,
        isr: isr_arc,
        flags,
        name: String::from(name),
    });
    crate::infof!("registered: irq={}, name={}", irq, name);
    Ok(())
}

pub fn run() -> Result<(), ()> {
    let mut sigmask = SigSet::empty();
    sigmask.add(libc::SIGHUP);
    for entry in IRQS.lock().iter() {
        sigmask.add(entry.irq as libc::c_int);
    }

    let ret = unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, sigmask.as_ptr(), core::ptr::null_mut())
    };
    if ret != 0 {
        crate::errorf!("pthread_sigmask failed: {}", std::io::Error::last_os_error());
        return Err(());
    }

    let barrier = Arc::new(Barrier::new(2));
    let barrier_for_thread = barrier.clone();

    let handle = thread::spawn(move || intr_main(barrier_for_thread, sigmask));
    *THREAD.lock() = Some(handle);

    barrier.wait();
    Ok(())
}

pub fn shutdown() {
    let handle = THREAD.lock().take();
    if let Some(handle) = handle {
        // Send SIGHUP to ourselves. The main thread has it blocked, so only
        // the dispatcher thread (waiting in sigwait) receives it and exits.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }
        let _ = handle.join();
    }
}

/// Raise an IRQ by sending its signal to the current process.
///
/// Async-signal-safe (libc::kill is on the POSIX list); usable from
/// signal handlers.
pub fn raise(irq: IrqNumber) {
    unsafe {
        libc::kill(libc::getpid(), irq as libc::c_int);
    }
}

fn intr_main(barrier: Arc<Barrier>, sigmask: SigSet) {
    let block_all = SigSet::full();
    unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, block_all.as_ptr(), core::ptr::null_mut());
    }
    crate::debugf!("start...");
    barrier.wait();

    loop {
        let mut sig: libc::c_int = 0;
        let err = unsafe { libc::sigwait(sigmask.as_ptr(), &mut sig) };
        if err != 0 {
            crate::errorf!(
                "sigwait failed: {}",
                std::io::Error::from_raw_os_error(err)
            );
            break;
        }
        if sig == libc::SIGHUP {
            break;
        }

        let matching: Vec<(IrqNumber, IsrArc, u32, String)> = {
            let irqs = IRQS.lock();
            irqs.iter()
                .filter(|e| e.irq == sig as IrqNumber)
                .map(|e| (e.irq, e.isr.clone(), e.flags, e.name.clone()))
                .collect()
        };
        for (irq, isr, entry_flags, name) in matching {
            if entry_flags & FLAG_QUIET == 0 {
                crate::debugf!("irq={}, name={}", irq, name);
            }
            isr(irq);
            if entry_flags & FLAG_SHARED == 0 {
                break;
            }
        }
    }
    crate::debugf!("terminated");
}
