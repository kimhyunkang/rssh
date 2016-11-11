use super::buf::AsyncBuf;
use super::DEFAULT_BUFSIZE;

use std::{cmp, io};
use std::io::{BufRead, Read};

use futures::{Async, Poll};
use tokio_core::io::Io;

pub struct AsyncBufReader<R> {
    inner: R,
    buf: AsyncBuf
}

impl <R> AsyncBufReader<R> {
    pub fn new(inner: R) -> AsyncBufReader<R> {
        AsyncBufReader::with_capacity(DEFAULT_BUFSIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: R) -> AsyncBufReader<R> {
        AsyncBufReader {
            inner: inner,
            buf: AsyncBuf::with_capacity(capacity)
        }
    }
}

impl <R: Read> AsyncBufReader<R> {
    fn fill_buf_no_eof(&mut self) -> io::Result<()> {
        let rsize = try!(self.inner.read(self.buf.get_mut()));
        if rsize == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected EOF"));
        }
        self.buf.fill(rsize);
        Ok(())
    }

    pub fn nb_read_exact(&mut self, n: usize) -> Poll<&[u8], io::Error> {
        if self.buf.data_size() >= n {
            Ok(Async::Ready(self.buf.consume_and_get(n)))
        } else {
            self.buf.reserve(n);
            if let Err(e) = self.fill_buf_no_eof() {
                if let io::ErrorKind::WouldBlock = e.kind() {
                    return Ok(Async::NotReady);
                } else {
                    return Err(e)
                }
            }

            if self.buf.data_size() < n {
                Ok(Async::NotReady)
            } else {
                Ok(Async::Ready(self.buf.consume_and_get(n)))
            }
        }
    }

    pub fn nb_read_until(&mut self, byte: u8, limit: usize) -> Poll<&[u8], io::Error> {
        if let Some(idx) = self.buf.get_ref().iter().position(|&c| c == byte) {
            return Ok(Async::Ready(self.buf.consume_and_get(idx)));
        } else {
            self.buf.reserve(limit);
            if let Err(e) = self.fill_buf_no_eof() {
                if let io::ErrorKind::WouldBlock = e.kind() {
                    return Ok(Async::NotReady);
                } else {
                    return Err(e)
                }
            }

            if let Some(idx) = self.buf.get_ref().iter().position(|&c| c == byte) {
                Ok(Async::Ready(self.buf.consume_and_get(idx)))
            } else if self.buf.data_size() < limit {
                Ok(Async::NotReady)
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "delimiter not found"))
            }
        }
    }
}

impl <R:Read> BufRead for AsyncBufReader<R> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let rsize = try!(self.inner.read(self.buf.get_mut()));
        self.buf.fill(rsize);
        Ok(self.buf.get_ref())
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.buf.consume(amt)
    }
}

impl <R:Read> Read for AsyncBufReader<R> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buf.capacity() < buf.len() && self.buf.is_empty() {
            return self.inner.read(buf);
        }

        if self.buf.data_size() < buf.len() {
            let rsize = try!(self.inner.read(self.buf.get_mut()));
            self.buf.fill(rsize);
        }

        let rsize = cmp::min(self.buf.data_size(), buf.len());
        buf[.. rsize].copy_from_slice(&self.buf.get_ref()[.. rsize]);
        self.buf.consume(rsize);
        Ok(rsize)
    }
}

pub trait AsyncPollRead {
    fn async_poll_read(&mut self) -> Async<()>;
}

impl <R: Io> AsyncPollRead for AsyncBufReader<R> {
    fn async_poll_read(&mut self) -> Async<()> {
        self.inner.poll_read()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{cmp, io};
    use std::io::{BufRead, Cursor, Read};
    use futures::Async;

    pub struct MockAsyncReader {
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for MockAsyncReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let datasize = cmp::min(buf.len(), self.buf.len() - self.pos);
            if datasize == 0 {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "data not ready"));
            }
            let new_pos = self.pos + datasize;
            buf[.. datasize].copy_from_slice(&self.buf[self.pos .. new_pos]);
            self.pos = new_pos;
            Ok(datasize)
        }
    }

    fn mock_async_reader(data: &[u8]) -> MockAsyncReader {
        MockAsyncReader {
            buf: data.to_vec(),
            pos: 0
        }
    }

    #[test]
    fn read_exact() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(16, reader);

        assert_eq!(Async::Ready(b"Hello".as_ref()), bufreader.nb_read_exact(5).expect("error!"));
    }

    #[test]
    fn read_exact_larger_than_buffer() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        assert_eq!(Async::Ready(b"Hello".as_ref()), bufreader.nb_read_exact(5).expect("error!"));
    }

    #[test]
    fn read_exact_with_small_buffer() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        assert_eq!(Async::Ready(b"Hell".as_ref()), bufreader.nb_read_exact(4).expect("error!"));
        assert_eq!(Async::Ready(b"o".as_ref()), bufreader.nb_read_exact(1).expect("error!"));
        assert_eq!(Async::Ready(b", ".as_ref()), bufreader.nb_read_exact(2).expect("error!"));
        assert_eq!(Async::Ready(b"world!".as_ref()), bufreader.nb_read_exact(6).expect("error!"));
    }

    #[test]
    fn read_exact_unexpected_eof() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        assert_eq!(Async::Ready(b"Hell".as_ref()), bufreader.nb_read_exact(4).expect("error!"));
        assert_eq!(Async::Ready(b"o".as_ref()), bufreader.nb_read_exact(1).expect("error!"));
        assert_eq!(Async::Ready(b", ".as_ref()), bufreader.nb_read_exact(2).expect("error!"));
        // The first call returns `NotReady`, then the second call returns `UnexpectedEof`
        assert_eq!(Async::NotReady, bufreader.nb_read_exact(7).expect("error!"));
        match bufreader.nb_read_exact(7) {
            Ok(x) => panic!("Expected EOF, but got {:?}", x),
            Err(e) => assert_eq!(io::ErrorKind::UnexpectedEof, e.kind())
        }
    }

    #[test]
    fn read_exact_async() {
        let reader = mock_async_reader(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        assert_eq!(Async::Ready(b"Hell".as_ref()), bufreader.nb_read_exact(4).expect("error!"));
        assert_eq!(Async::Ready(b"o".as_ref()), bufreader.nb_read_exact(1).expect("error!"));
        assert_eq!(Async::Ready(b", ".as_ref()), bufreader.nb_read_exact(2).expect("error!"));

        // The call returns `NotReady` indefinitely if the data is too short
        assert_eq!(Async::NotReady, bufreader.nb_read_exact(7).expect("error!"));
        assert_eq!(Async::NotReady, bufreader.nb_read_exact(7).expect("error!"));

        assert_eq!(Async::Ready(b"world!".as_ref()), bufreader.nb_read_exact(6).expect("error!"));
    }

    #[test]
    fn read() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        let mut buf = Vec::new();

        assert_eq!(13, bufreader.read_to_end(&mut buf).expect("error!"));

        assert_eq!(b"Hello, world!".as_ref(), buf.as_slice());
    }

    #[test]
    fn bufread() {
        let reader = Cursor::new(b"Hello, world!");
        let mut bufreader = AsyncBufReader::with_capacity(4, reader);

        let mut buf = Vec::new();

        assert_eq!(7, bufreader.read_until(b' ', &mut buf).expect("error!"));

        assert_eq!(b"Hello, ".as_ref(), buf.as_slice());
    }
}
