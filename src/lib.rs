extern crate futures;
extern crate rand;
#[macro_use]
extern crate tokio_core;

pub mod async;
pub mod handshake;
pub mod transport;

pub static SSH_MSG_KEYINIT: u8 = 20;
