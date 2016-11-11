use super::buf::AsyncBuf;
use super::DEFAULT_BUFSIZE;

use std::{cmp, io};
use std::io::Write;

use futures::{Async, Poll};

#[derive(Debug)]
pub struct AsyncBufWriter<W: Write> {
    inner: Option<W>,
    buf: AsyncBuf,
    panicked: bool
}

#[derive(Debug)]
pub struct IntoInnerError<W>(W, io::Error);

impl <W: Write> AsyncBufWriter<W> {
    pub fn new(inner: W) -> AsyncBufWriter<W> {
        AsyncBufWriter::with_capacity(DEFAULT_BUFSIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: W) -> AsyncBufWriter<W> {
        AsyncBufWriter {
            inner: Some(inner),
            buf: AsyncBuf::with_capacity(capacity),
            panicked: false
        }
    }

    pub fn nb_into_inner(mut self) -> Poll<W, IntoInnerError<AsyncBufWriter<W>>> {
        match self.nb_flush() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready(())) => Ok(Async::Ready(self.inner.take().unwrap())),
            Err(e) => Err(IntoInnerError(self, e))
        }
    }

    #[inline]
    fn write_inner(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.panicked = true;
        let res = self.inner.as_mut().expect("attempted to write after into_inner called").write(buf);
        self.panicked = false;
        res
    }

    #[inline]
    fn flush_inner(&mut self) -> io::Result<()> {
        self.panicked = true;
        let res = self.inner.as_mut().expect("attempted to flush after into_inner called").flush();
        self.panicked = false;
        res
    }

    pub fn nb_flush_buf(&mut self) -> Poll<(), io::Error> {
        self.panicked = true;
        let amt = try_nb!(self.inner.as_mut().expect("attempted to flush after into_inner called").write(self.buf.get_ref()));
        self.panicked = false;
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
            try_nb!(self.flush_inner());
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
            match self.write_inner(buf) {
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

impl <W: Write> Write for AsyncBufWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.buf.reserve_size() {
            try!(self.nb_flush_buf());
        }

        if self.buf.is_empty() && self.buf.capacity() < buf.len() {
            self.write_inner(buf)
        } else {
            let datasize = cmp::min(self.buf.reserve_size(), buf.len());
            self.buf.get_mut()[.. datasize].copy_from_slice(&buf[.. datasize]);
            Ok(datasize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        while let Async::NotReady = try!(self.nb_flush_buf()) {
            ()
        }

        self.flush_inner()
    }
}

impl <W: Write> Drop for AsyncBufWriter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.panicked {
            let _r = self.nb_flush_buf();
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

            if let Async::Ready(w) = bufwriter.nb_into_inner().expect("error!") {
                w
            } else {
                panic!("not ready");
            }
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

            if let Async::Ready(w) = bufwriter.nb_into_inner().expect("error!") {
                w
            } else {
                panic!("not ready");
            }
        };

        let wsize = writer.position() as usize;
        assert_eq!(b"Hello, world!".len(), wsize);

        let buf = writer.into_inner();
        assert_eq!(b"Hello, world!".as_ref(), &buf[.. wsize]);
    }
}
