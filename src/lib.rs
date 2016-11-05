extern crate futures;
#[macro_use]
extern crate tokio_core;

use std::io::{BufRead, Write};
use std::io;
use std::mem;

use futures::{Async, Future, Poll};

pub fn exchange_version<R: BufRead, W: Write>(reader: R, writer: W, version_string: &str, comment: &str) -> VersionExchange<R, W, Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    write!(buf, "SSH-2.0-{} {}\r\n", version_string, comment).unwrap();
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    VersionExchange {
        inner: Some(Inner {
                   reader: reader,
                   writer: writer,
                   state: State::Writing { buf: buf, pos: 0 }
               })
    }
}

pub struct VersionExchange<R, W, B> {
    inner: Option<Inner<R, W, B>>
}

struct Inner<R, W, B> {
    reader: R,
    writer: W,
    state: State<B>
}

enum State<B> {
    Writing {
        buf: B,
        pos: usize
    },
    Reading {
        buf: Vec<u8>,
    }
}

fn zero_write() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "zero-length write")
}

impl<R, W, B> Future for VersionExchange<R, W, B>
    where R: BufRead, W: Write, B: AsRef<[u8]>
{
    type Item = (R, W, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(R, W, Vec<u8>), io::Error> {
        let res = if let Some(ref mut inner) = self.inner {
            inner.poll()
        } else {
            panic!("poll VersionExchange after it's done");
        };

        match res {
            Ok(Async::Ready(())) => match mem::replace(&mut self.inner, None) {
                Some(Inner { reader, writer, state: State::Reading { buf } }) =>
                    Ok(Async::Ready((reader, writer, buf))),
                _ =>
                    unreachable!()
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e)
        }
    }
}

impl<R, W, B> Inner<R, W, B>
    where R: BufRead, W: Write, B: AsRef<[u8]>
{
    fn poll(&mut self) -> Poll<(), io::Error> {
        match self.state {
            State::Writing { ref buf, ref mut pos } => {
                let buf = buf.as_ref();
                while *pos < buf.len() {
                    let n = try_nb!(self.writer.write(&buf[*pos ..]));
                    *pos += n;
                    if n == 0 {
                        return Err(zero_write())
                    }
                }
            },
            State::Reading { ref mut buf } => {
                try_nb!(self.reader.read_until(b'\n', buf));
                return Ok(Async::Ready(()));
            }
        }

        self.state = State::Reading { buf: Vec::with_capacity(256) };

        self.poll()
    }
}
