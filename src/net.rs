//! Network stack lifecycle.

pub fn init() -> Result<(), ()> {
    crate::infof!("initialize...");
    crate::platform::init()?;
    crate::infof!("success");
    Ok(())
}

pub fn run() -> Result<(), ()> {
    crate::infof!("startup...");
    crate::platform::run()?;
    crate::infof!("success");
    Ok(())
}

pub fn shutdown() {
    crate::infof!("shutting down...");
    crate::platform::shutdown();
    crate::infof!("success");
}
