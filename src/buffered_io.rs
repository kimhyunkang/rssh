use async_buf::AsyncBufRead;

use std::io;
use std::io::{BufRead, BufWriter, Read, Write};

use futures::Poll;
use tokio_core::io::{Io, ReadHalf, WriteHalf};

static DEFAULT_BUFSIZE: usize = 4096;

pub struct BufferedIo<S: Io> {
    reader: AsyncBufRead<ReadHalf<S>>,
    writer: BufWriter<WriteHalf<S>>,
}

impl <S: Io> BufferedIo<S> {
    pub fn new(stream: S) -> BufferedIo<S> {
        BufferedIo::with_capacity(DEFAULT_BUFSIZE, stream)
    }

    pub fn with_capacity(capacity: usize, stream: S) -> BufferedIo<S> {
        let (rd, wr) = stream.split();
        BufferedIo {
            reader: AsyncBufRead::with_capacity(capacity, rd),
            writer: BufWriter::with_capacity(capacity, wr)
        }
    }

    #[inline]
    pub fn nb_read_exact(&mut self, n: usize) -> Poll<&[u8], io::Error> {
        self.reader.nb_read_exact(n)
    }
}

impl <S:Io> Read for BufferedIo<S> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
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
        self.reader.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt)
    }
}
