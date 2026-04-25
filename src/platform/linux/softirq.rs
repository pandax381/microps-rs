//! Linux softirq subsystem.
//!
//! Defers work out of the hard IRQ path via SIGUSR1 raised through the
//! intr dispatcher. The single softirq handler is net::softirq_handler,
//! which drains the input queue and dispatches packets to protocol
//! handlers.

use alloc::boxed::Box;

use crate::platform::linux::intr;

const SOFT_IRQ: intr::IrqNumber = libc::SIGUSR1 as intr::IrqNumber;

pub fn raise() {
    intr::raise(SOFT_IRQ);
}

fn isr(_irq: intr::IrqNumber) {
    crate::net::softirq_handler();
}

pub fn init() -> Result<(), ()> {
    intr::register(SOFT_IRQ, Box::new(isr), 0, "softirq")?;
    Ok(())
}

pub fn run() -> Result<(), ()> {
    Ok(())
}

pub fn shutdown() {}
