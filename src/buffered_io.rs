use std::{cmp, io};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};

use tokio_core::io::{Io, ReadHalf, WriteHalf};

static DEFAULT_BUFSIZE: usize = 4096;

pub struct BufferedIo<S: Io> {
    reader: ReadHalf<S>,
    writer: BufWriter<WriteHalf<S>>,
    rd_buf: Vec<u8>,
    rd_pos: usize,
    rd_cap: usize
}

impl <S: Io> BufferedIo<S> {
    pub fn new(stream: S) -> BufferedIo<S> {
        BufferedIo::with_capacity(DEFAULT_BUFSIZE, stream)
    }

    pub fn with_capacity(capacity: usize, stream: S) -> BufferedIo<S> {
        let (rd, wr) = stream.split();
        BufferedIo {
            reader: rd,
            writer: BufWriter::with_capacity(capacity, wr),
            rd_buf: vec![0; capacity],
            rd_pos: 0,
            rd_cap: 0,
        }
    }

    fn try_realign(&mut self) -> bool {
        if self.rd_cap == self.rd_buf.len() {
            let data_len = self.rd_cap - self.rd_pos;
            if data_len * 2 > self.rd_buf.len() {
                self.rd_buf.resize(self.rd_cap * 2, 0);
            }
            let (dst, src) = self.rd_buf.split_at_mut(self.rd_cap);
            dst[.. data_len].copy_from_slice(src);
            true
        } else {
            false
        }
    }

    fn fill_buf_no_eof(&mut self) -> io::Result<()> {
        let rsize = try!(self.reader.read(&mut self.rd_buf[self.rd_cap ..]));
        if rsize == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        self.rd_cap += rsize;
        Ok(())
    }

    pub fn nb_read_exact(&mut self, n: usize) -> Result<Option<&[u8]>, io::Error> {
        if self.rd_pos + n > self.rd_cap {
            try!(self.fill_buf_no_eof());
        }

        if self.rd_pos + n > self.rd_cap {
            if self.try_realign() {
                try!(self.fill_buf_no_eof());
            }
        }

        if self.rd_pos + n > self.rd_cap {
            Ok(None)
        } else {
            let buf = &self.rd_buf[self.rd_pos .. self.rd_pos + n];
            self.rd_pos += n;
            Ok(Some(buf))
        }
    }
}

impl <S:Io> Read for BufferedIo<S> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any buffered data and we're doing a massive read
        // (larger than our internal buffer), bypass our internal buffer
        // entirely.
        if self.rd_pos == self.rd_cap && buf.len() >= self.rd_buf.len() {
            return self.reader.read(buf);
        }
        let nread = {
            let mut rem = try!(self.fill_buf());
            try!(rem.read(buf))
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl <S:Io> Write for BufferedIo<S> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl <S:Io> BufRead for BufferedIo<S> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.rd_cap += try!(self.reader.read(&mut self.rd_buf[self.rd_cap ..]));

        Ok(&self.rd_buf[self.rd_pos .. self.rd_cap])
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.rd_pos = self.rd_pos + amt;

        // All the buffer is consumed. Reset to read the new buffer
        if self.rd_pos >= self.rd_cap {
            self.rd_pos = 0;
        }
    }
}
