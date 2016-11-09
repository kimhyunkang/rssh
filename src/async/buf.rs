use std::cmp;

use super::DEFAULT_BUFSIZE;

#[derive(Debug)]
pub struct AsyncBuf {
    buf: Vec<u8>,
    pos: usize,
    cap: usize
}

impl AsyncBuf {
    pub fn new() -> AsyncBuf {
        AsyncBuf::with_capacity(DEFAULT_BUFSIZE)
    }

    pub fn with_capacity(capacity: usize) -> AsyncBuf {
        AsyncBuf {
            buf: vec![0; capacity],
            pos: 0,
            cap: 0
        }
    }

    pub fn try_reserve(&mut self, n: usize) -> bool {
        if self.cap + n <= self.buf.len() {
            return true;
        }

        let data_len = self.cap - self.pos;
        if data_len > self.pos || data_len + n > self.buf.len() {
            false
        } else {
            let (dst, src) = self.buf.split_at_mut(self.pos);
            dst[.. data_len].copy_from_slice(&src[.. data_len]);
            self.pos = 0;
            self.cap = data_len;
            true
        }
    }

    pub fn reserve(&mut self, n: usize) {
        if !self.try_reserve(n) {
            let target_cap = self.cap + n;
            let mut new_capacity = self.buf.len();
            while new_capacity < target_cap {
                new_capacity *= 2;
            }
            self.buf.resize(new_capacity, 0);
        }
    }

    #[inline]
    pub fn data_size(&self) -> usize {
        self.cap - self.pos
    }

    #[inline]
    pub fn get_ref(&self) -> &[u8] {
        &self.buf[self.pos .. self.cap]
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.cap ..]
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data_size() == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn fill(&mut self, n: usize) {
        self.cap = cmp::min(self.cap + n, self.buf.len());
    }

    #[inline]
    pub fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;
        }
    }

    pub fn consume_and_get(&mut self, n: usize) -> &[u8] {
        if self.pos + n > self.cap {
            panic!("consuming larger than actual data");
        }

        let data = &self.buf[self.pos .. self.pos + n];
        self.pos += n;
        if self.pos >= self.cap {
            self.pos = 0;
            self.cap = 0;
        }
        data
    }

    #[inline]
    fn write_buf(&mut self, buf: &[u8]) {
        let new_cap = self.cap + buf.len();
        self.buf[self.cap .. new_cap].copy_from_slice(buf);
        self.cap = new_cap;
    }

    pub fn try_write_all(&mut self, buf: &[u8]) -> bool {
        if self.cap + buf.len() <= self.buf.len() {
            self.write_buf(buf);
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn write_all(&mut self, buf: &[u8]) {
        self.reserve(buf.len());
        self.write_buf(buf);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn async_buf_try_write_all() {
        let mut buf = AsyncBuf::with_capacity(8);
        assert_eq!(true, buf.try_write_all(b"Hello"));
        assert_eq!(b"Hello", buf.get_ref());
    }

    #[test]
    fn async_buf_write_all() {
        let mut buf = AsyncBuf::with_capacity(8);
        assert_eq!(true, buf.try_write_all(b"Hello"));
        assert_eq!(false, buf.try_write_all(b", world!"));
        assert_eq!(b"Hello", buf.get_ref());
        buf.write_all(b", world!");
        assert_eq!(b"Hello, world!", buf.get_ref());
    }

    #[test]
    fn async_buf_try_reserve() {
        let mut buf = AsyncBuf::with_capacity(8);
        assert_eq!(0, buf.data_size());
        assert_eq!(true, buf.try_write_all(b"Hello"));
        assert_eq!(5, buf.data_size());
        assert_eq!(b"Hell", buf.consume_and_get(4));
        assert_eq!(1, buf.data_size());
        assert_eq!(true, buf.try_reserve(7));
        assert_eq!(8, buf.capacity());
        assert_eq!(b"o", buf.get_ref());
        assert_eq!(7, buf.get_mut().len());
    }

    #[test]
    fn async_buf_reserve() {
        let mut buf = AsyncBuf::with_capacity(8);
        assert_eq!(true, buf.try_write_all(b"Hello"));
        assert_eq!(b"He", buf.consume_and_get(2));
        assert_eq!(false, buf.try_reserve(6));
        buf.reserve(6);
        assert_eq!(b"llo", buf.get_ref());
        assert!(buf.get_mut().len() >= 6);
    }

    #[test]
    fn async_buf_consume() {
        let mut buf = AsyncBuf::with_capacity(16);
        assert_eq!(true, buf.try_write_all(b"Hello, world!"));
        buf.consume(7);
        assert_eq!(b"world!", buf.get_ref());
    }
}
