//! Log output.
//!
//! Two output channels:
//! - `errorf!` / `warnf!` / `infof!` / `debugf!` emit decorated messages
//!   (level, call site, timestamp).
//! - `printf!` emits raw text, used by packet dumps.

use core::fmt;

#[doc(hidden)]
pub fn log_output(level: char, file: &str, line: u32, function: &str, args: fmt::Arguments) {
    crate::platform::log_output(level, file, line, function, args);
}

#[doc(hidden)]
pub fn print_output(args: fmt::Arguments) {
    crate::platform::print_output(args);
}

/// Returns the caller's function path at compile time.
///
/// Rust has no `__func__`, so we use the nested-fn `type_name` trick:
/// `type_name` of the inner fn yields `"<crate>::<outer_fn>::__log_fn_marker"`,
/// so stripping the 17-char suffix gives the outer path.
#[doc(hidden)]
#[macro_export]
macro_rules! __function_path {
    () => {{
        fn __log_fn_marker() {}
        fn __type_name_of<T>(_: T) -> &'static str {
            ::core::any::type_name::<T>()
        }
        let name = __type_name_of(__log_fn_marker);
        &name[..name.len() - 17]
    }};
}

#[macro_export]
macro_rules! errorf {
    ($($arg:tt)*) => {
        $crate::log::log_output(
            'E', file!(), line!(), $crate::__function_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! warnf {
    ($($arg:tt)*) => {
        $crate::log::log_output(
            'W', file!(), line!(), $crate::__function_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! infof {
    ($($arg:tt)*) => {
        $crate::log::log_output(
            'I', file!(), line!(), $crate::__function_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! debugf {
    ($($arg:tt)*) => {
        $crate::log::log_output(
            'D', file!(), line!(), $crate::__function_path!(), format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! printf {
    ($($arg:tt)*) => {
        $crate::log::print_output(format_args!($($arg)*))
    };
}
