use super::bufreader::AsyncBufReader;
use super::bufwriter::AsyncBufWriter;

use std::io;
use std::io::{BufRead, Read, Write};

use futures::Poll;
use tokio_core::io::{Io, ReadHalf, WriteHalf};

static DEFAULT_BUFSIZE: usize = 4096;

pub struct BufferedIo<S: Read + Write> {
    reader: AsyncBufReader<ReadHalf<S>>,
    writer: AsyncBufWriter<WriteHalf<S>>,
}

impl <S: Read + Write + Io> BufferedIo<S> {
    pub fn new(stream: S) -> BufferedIo<S> {
        BufferedIo::with_capacity(DEFAULT_BUFSIZE, stream)
    }

    pub fn with_capacity(capacity: usize, stream: S) -> BufferedIo<S> {
        let (rd, wr) = stream.split();
        BufferedIo {
            reader: AsyncBufReader::with_capacity(capacity, rd),
            writer: AsyncBufWriter::with_capacity(capacity, wr)
        }
    }

    #[inline]
    pub fn nb_read_exact(&mut self, n: usize) -> Poll<&[u8], io::Error> {
        self.reader.nb_read_exact(n)
    }

    #[inline]
    pub fn nb_read_until(&mut self, byte: u8, limit: usize) -> Poll<&[u8], io::Error> {
        self.reader.nb_read_until(byte, limit)
    }

    #[inline]
    pub fn nb_write_exact(&mut self, buf: &[u8]) -> Poll<(), io::Error> {
        self.writer.nb_write_exact(buf)
    }

    #[inline]
    pub fn nb_flush(&mut self) -> Poll<(), io::Error> {
        self.writer.nb_flush()
    }

    #[inline]
    pub fn nb_flush_buf(&mut self) -> Poll<(), io::Error> {
        self.writer.nb_flush_buf()
    }
}

impl <S: Read + Write> Read for BufferedIo<S> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl <S: Read + Write> Write for BufferedIo<S> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl <S: Read + Write> BufRead for BufferedIo<S> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt)
    }
}
