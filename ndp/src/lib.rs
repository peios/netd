//! IPv6 neighbour discovery, for a host that does its own thinking.
//!
//! The kernel's router-advertisement handling is switched off on Peios
//! (`accept_ra = 0`): policy about what an RA means — which addresses to
//! form, which router to believe, what DNS to use — lives in netd, in one
//! place, like every other network decision. This crate is the pure part:
//! the ICMPv6 codec ([`packet`]) and the per-interface SLAAC state machine
//! ([`engine`]), clock-injected and socket-free in the same shape as the
//! `dhcp4` crate. The caller feeds it time and packets and performs the
//! [`Action`]s it returns.

pub mod engine;
#[cfg(test)]
mod fuzz_tests;
pub mod packet;

pub use engine::{Action, Config, DesiredAddress, Engine};
pub use packet::{Dnssl, PrefixInfo, Rdnss, RouterAdvert};
