use std::io;
use std::io::{BufRead, Read};

static DEFAULT_BUFSIZE: usize = 4096;

pub struct AsyncBufRead<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize
}

impl <R> AsyncBufRead<R> {
    pub fn new(inner: R) -> AsyncBufRead<R> {
        AsyncBufRead::with_capacity(DEFAULT_BUFSIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: R) -> AsyncBufRead<R> {
        AsyncBufRead {
            inner: inner,
            buf: vec![0; capacity],
            pos: 0,
            cap: 0
        }
    }
}

impl <R: Read> AsyncBufRead<R> {
    fn reserve(&mut self, n: usize) {
        if self.pos + n > self.buf.len() {
            return;
        }

        let data_len = self.cap - self.pos;
        if data_len > self.pos || n > self.buf.len() {
            let target_cap = self.pos + n;
            let mut new_capacity = self.buf.len();
            while new_capacity < target_cap {
                new_capacity *= 2;
            }
            self.buf.resize(new_capacity, 0);
        } else {
            let (dst, src) = self.buf.split_at_mut(self.pos);
            dst[.. data_len].copy_from_slice(&src[.. data_len]);
            self.pos = 0;
            self.cap = data_len;
        }
    }

    fn fill_buf_no_eof(&mut self) -> io::Result<()> {
        let rsize = try!(self.inner.read(&mut self.buf[self.cap ..]));
        if rsize == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        self.cap += rsize;
        Ok(())
    }

    pub fn nb_read_exact(&mut self, n: usize) -> Result<Option<&[u8]>, io::Error> {
        if self.pos + n > self.cap {
            self.reserve(n);
            try!(self.fill_buf_no_eof());
        }

        if self.pos + n > self.cap {
            Ok(None)
        } else {
            let buf = &self.buf[self.pos .. self.pos + n];
            self.pos += n;
            if self.pos == self.cap {
                self.pos = 0;
                self.cap = 0;
            }
            Ok(Some(buf))
        }
    }
}

impl <S:Read> Read for AsyncBufRead<S> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any buffered data and we're doing a massive read
        // (larger than our internal buffer), bypass our internal buffer
        // entirely.
        if self.pos == self.cap && buf.len() >= self.buf.len() {
            return self.inner.read(buf);
        }
        let nread = {
            let mut rem = try!(self.fill_buf());
            try!(rem.read(buf))
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl <S:Read> BufRead for AsyncBufRead<S> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.cap += try!(self.inner.read(&mut self.buf[self.cap ..]));

        Ok(&self.buf[self.pos .. self.cap])
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.pos = self.pos + amt;

        // All the buffer is consumed. Reset to read the new buffer
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;
        }
    }
}
