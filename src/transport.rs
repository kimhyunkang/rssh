use std::io;
use std::io::{BufRead, Write};

use tokio_core::io::{ReadUntil, WriteAll};

pub struct Vex<S> {
    state: VexState<S>
}

enum VexState<S> {
    Writing(WriteAll<S, Vec<u8>>),
    Reading(ReadUntil<S>),
    Done
}

impl<S> Future for VersionExchange<S>
    where S: BufRead + Write
{
    type Item = (S, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(S, Vec<u8>), io::Error> {
        let next_state = match self.state {
            VexState::Writing(ref mut s) => match s.poll() {
                Ok(Async::Ready((io, _))) => VexState::Reading(read_until(io, b'\n', Vec::with_capacity(256)))
            }
        }
    }
}
