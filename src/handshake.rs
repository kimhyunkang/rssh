use buffered_io::BufferedIo;

use std::{fmt, io};
use std::io::Write;
use futures::Future;
use tokio_core::io::{Io, flush, read_until, write_all};

pub enum VexError {
    IoError(io::Error),
    InvalidVersionExchange
}

impl fmt::Display for VexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VexError::IoError(ref e) => e.fmt(f),
            VexError::InvalidVersionExchange => write!(f, "InvalidVersionExchange")
        }
    }
}

pub fn version_exchange<S: Io+Send+'static>(stream: BufferedIo<S>, version_string: &str, comment: &str)
        -> Box<Future<Item=(BufferedIo<S>, Vec<u8>), Error=VexError>>
    where S: Io
{
    let mut buf = Vec::with_capacity(256);
    write!(buf, "SSH-2.0-{} {}\r\n", version_string, comment).unwrap();
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    write_all(stream, buf).and_then(|(stream, _)| {
        flush(stream)
    }).and_then(|stream| {
        read_until(stream, b'\n', Vec::with_capacity(256))
    }).map_err(|e| {
        VexError::IoError(e)
    }).and_then(|(stream, buf)| {
        if buf.starts_with(b"SSH-2.0-") && buf.ends_with(b"\r\n") {
            Ok((stream, buf[8 .. buf.len()-2].to_vec()))
        } else {
            Err(VexError::InvalidVersionExchange)
        }
    }).boxed()
}
