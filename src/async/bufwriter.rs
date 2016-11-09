use super::buf::AsyncBuf;
use super::DEFAULT_BUFSIZE;

use std::io;
use std::io::Write;

use futures::{Async, Poll};

pub struct AsyncBufWriter<W> {
    inner: W,
    buf: AsyncBuf
}

impl <W> AsyncBufWriter<W> {
    pub fn new(inner: W) -> AsyncBufWriter<W> {
        AsyncBufWriter::with_capacity(DEFAULT_BUFSIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: W) -> AsyncBufWriter<W> {
        AsyncBufWriter {
            inner: inner,
            buf: AsyncBuf::with_capacity(capacity)
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl <W: Write> AsyncBufWriter<W> {
    pub fn nb_flush_buf(&mut self) -> Poll<(), io::Error> {
        let amt = try_nb!(self.inner.write(self.buf.get_ref()));
        self.buf.consume(amt);
        if self.buf.is_empty() {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }

    pub fn nb_flush(&mut self) -> Poll<(), io::Error> {
        if !self.buf.is_empty() {
            if let Async::NotReady = try!(self.nb_flush_buf()) {
                return Ok(Async::NotReady);
            }
        }

        if self.buf.is_empty() {
            try_nb!(self.inner.flush());
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }

    pub fn nb_write_exact(&mut self, buf: &[u8]) -> Poll<(), io::Error> {
        if buf.len() > self.buf.capacity() {
            if !self.buf.is_empty() {
                if let Async::NotReady = try!(self.nb_flush_buf()) {
                    return Ok(Async::NotReady);
                }
            }
            match self.inner.write(buf) {
                Ok(amt) => {
                    self.buf.write_all(&buf[amt ..]);
                    Ok(Async::Ready(()))
                }
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(Async::NotReady),
                    _ => Err(e)
                }
            }
        } else {
            if self.buf.try_write_all(buf) {
                Ok(Async::Ready(()))
            } else {
                match try!(self.nb_flush_buf()) {
                    Async::NotReady =>
                        Ok(Async::NotReady),
                    Async::Ready(()) =>
                        if self.buf.try_write_all(buf) {
                            Ok(Async::Ready(()))
                        } else {
                            Ok(Async::NotReady)
                        }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Cursor;
    use futures::Async;

    #[test]
    fn nb_write_exact() {
        let writer = {
            let buf = vec![0u8; 16];
            let writer = Cursor::new(buf);
            let mut bufwriter = AsyncBufWriter::with_capacity(4, writer);

            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"Hell").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"o, ").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"wor").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"ld!").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_flush().expect("error!"));

            bufwriter.into_inner()
        };

        let wsize = writer.position() as usize;
        assert_eq!(b"Hello, world!".len(), wsize);

        let buf = writer.into_inner();
        assert_eq!(b"Hello, world!".as_ref(), &buf[.. wsize]);
    }

    #[test]
    fn nb_write_exact_larger_than_buf() {
        let writer = {
            let buf = vec![0u8; 16];
            let writer = Cursor::new(buf);
            let mut bufwriter = AsyncBufWriter::with_capacity(4, writer);

            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"Hello, ").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_write_exact(b"world!").expect("error!"));
            assert_eq!(Async::Ready(()), bufwriter.nb_flush().expect("error!"));

            bufwriter.into_inner()
        };

        let wsize = writer.position() as usize;
        assert_eq!(b"Hello, world!".len(), wsize);

        let buf = writer.into_inner();
        assert_eq!(b"Hello, world!".as_ref(), &buf[.. wsize]);
    }
}
