#![feature(proc_macro)]
#![feature(try_from)]

extern crate futures;
extern crate rand;
extern crate ring;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate tokio_core;
extern crate untrusted;

#[cfg(test)]
extern crate rustc_serialize;

pub mod async;
pub mod handshake;
pub mod key;
pub mod packet;
pub mod transport;

pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEXDH_INIT: u8 = 30;
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
