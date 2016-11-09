use super::buf::AsyncBuf;
use super::DEFAULT_BUFSIZE;

use std::io;
use std::io::Read;

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
    use std::io::{Cursor, Read};
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
}
