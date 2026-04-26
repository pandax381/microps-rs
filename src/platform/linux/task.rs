//! Linux task management for blocking primitives.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use std::sync::{Condvar, Mutex as StdMutex};

use spin::Mutex;

use crate::platform::linux::intr;

const TASK_IRQ: intr::IrqNumber = libc::SIGUSR2 as intr::IrqNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    Notified,
    Interrupted,
}

#[derive(Debug, Clone, Copy)]
pub struct Snapshot(u64);

struct TaskState {
    generation: u64,
    interrupted: bool,
    wc: u32,
}

pub struct Task {
    state: StdMutex<TaskState>,
    cv: Condvar,
}

impl Task {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(self.state.lock().unwrap().generation)
    }

    pub fn wait_after(&self, snapshot: Snapshot) -> WaitResult {
        let mut s = self.state.lock().unwrap();
        if s.interrupted {
            if s.wc == 0 {
                s.interrupted = false;
            }
            return WaitResult::Interrupted;
        }
        s.wc += 1;
        // Wake immediately if generation advanced after the snapshot (lost-wakeup guard).
        s = self
            .cv
            .wait_while(s, |s| s.generation == snapshot.0 && !s.interrupted)
            .unwrap();
        s.wc -= 1;
        if s.interrupted {
            if s.wc == 0 {
                s.interrupted = false;
            }
            WaitResult::Interrupted
        } else {
            WaitResult::Notified
        }
    }

    pub fn notify(&self) {
        let mut s = self.state.lock().unwrap();
        s.generation = s.generation.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn interrupt(&self) {
        let mut s = self.state.lock().unwrap();
        if !s.interrupted {
            s.interrupted = true;
            self.cv.notify_all();
        }
    }
}

static TASKS: Mutex<Vec<Weak<Task>>> = Mutex::new(Vec::new());

pub fn new_task() -> Arc<Task> {
    let task = Arc::new(Task {
        state: StdMutex::new(TaskState {
            generation: 0,
            interrupted: false,
            wc: 0,
        }),
        cv: Condvar::new(),
    });
    let mut tasks = TASKS.lock();
    tasks.retain(|w| w.strong_count() > 0);
    tasks.push(Arc::downgrade(&task));
    task
}

fn isr(_irq: intr::IrqNumber) {
    let tasks: Vec<Arc<Task>> = TASKS
        .lock()
        .iter()
        .filter_map(|w| w.upgrade())
        .collect();
    for task in tasks {
        task.interrupt();
    }
}

pub fn init() -> Result<(), ()> {
    intr::register(TASK_IRQ, Box::new(isr), 0, "task")?;
    Ok(())
}

pub fn run() -> Result<(), ()> {
    Ok(())
}

pub fn shutdown() {}
