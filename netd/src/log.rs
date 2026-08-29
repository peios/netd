//! Lines on stderr. peinit captures them and forwards to the log collector;
//! netd does not choose a format or a destination.

use std::fmt::Arguments;
use std::io::Write;

fn emit(level: &str, args: Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "netd: {level}: {args}");
}

pub fn info(args: Arguments<'_>) {
    emit("info", args);
}

pub fn warn(args: Arguments<'_>) {
    emit("warn", args);
}

pub fn error(args: Arguments<'_>) {
    emit("error", args);
}
