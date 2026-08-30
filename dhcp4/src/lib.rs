//! A DHCPv4 client with no I/O.
//!
//! Two halves. [`packet`] encodes and decodes DHCP messages (RFC 2131 wire
//! format, RFC 2132 options, RFC 3396 is *not* supported — options are not
//! concatenated across duplicates, since no server we care about splits
//! them). [`client`] is the state machine: it is told the time and what
//! arrived, and answers with what to send and what changed. The caller owns
//! sockets, timers and the interface.
//!
//! Keeping the machine free of sockets is what makes it testable: every
//! transition in RFC 2131 §4.4 is exercised without a network.

pub mod client;
pub mod packet;

pub use client::{Action, Client, Config, Destination, State};
pub use packet::{Lease, Message, MessageType, Options, StaticRoute};

#[cfg(test)]
mod fuzz_tests;
#[cfg(test)]
mod adversarial_tests;
