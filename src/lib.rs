#![feature(proc_macro)]

extern crate futures;
extern crate rand;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate tokio_core;

pub mod async;
pub mod packet;
pub mod handshake;
pub mod transport;

pub const SSH_MSG_KEYINIT: u8 = 20;
pub const SSH_MSG_KEXDH_INIT: u8 = 30;
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
