use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;

use std::io;
use std::io::{Read, Write};

use futures::{Async, Future, Poll};
use rand::Rng;

pub struct UnencryptedStream<R: Read> {
    inner: Option<AsyncBufReader<R>>,
    rd_header: Option<(usize, usize)>
}

pub fn ntoh(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) + ((buf[1] as u32) << 16) + ((buf[2] as u32) << 8) + (buf[3] as u32)
}

pub fn hton(n: u32) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf[0] = (n >> 24) as u8;
    buf[1] = ((n >> 16) & 0xff) as u8;
    buf[2] = ((n >> 8) & 0xff) as u8;
    buf[3] = (n & 0xff) as u8;

    buf
}

impl <R: Read> UnencryptedStream<R> {
    pub fn new(stream: AsyncBufReader<R>) -> UnencryptedStream<R> {
        UnencryptedStream {
            inner: Some(stream),
            rd_header: None
        }
    }

    pub fn nb_read_packet<'r>(&'r mut self) -> Poll<&'r [u8], io::Error> {
        match self.rd_header {
            None => {
                match try!(self.inner.as_mut().unwrap().nb_read_exact(5)) {
                    Async::NotReady => return Ok(Async::NotReady),
                    Async::Ready(buf) => {
                        let pkt_len = ntoh(&buf[.. 4]) as usize;
                        let pad_len = buf[4] as usize;
                        if pkt_len < 16 || pkt_len < pad_len + 1 {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid header"));
                        }
                        self.rd_header = Some((pkt_len, pad_len));
                    }
                };
                self.nb_read_packet()
            },
            Some((pkt_len, pad_len)) => match try!(self.inner.as_mut().unwrap().nb_read_exact(pkt_len - 1)) {
                Async::NotReady => Ok(Async::NotReady),
                Async::Ready(buf) => {
                    self.rd_header = None;
                    Ok(Async::Ready(&buf[.. pkt_len - pad_len - 1]))
                }
            }
        }
    }

    pub fn into_inner(&mut self) -> AsyncBufReader<R> {
        self.inner.take().unwrap()
    }
}

pub struct UnencryptedReadPacket<R: Read> {
    inner: UnencryptedStream<R>
}

pub fn unencrypted_read_packet<R: Read>(stream: AsyncBufReader<R>) -> UnencryptedReadPacket<R> {
    UnencryptedReadPacket { inner: UnencryptedStream::new(stream) }
}

impl <R: Read> Future for UnencryptedReadPacket<R> {
    type Item = (AsyncBufReader<R>, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(AsyncBufReader<R>, Vec<u8>), io::Error> {
        let data = match self.inner.nb_read_packet() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(slice)) => slice.to_vec(),
            Err(e) => return Err(e)
        };

        Ok(Async::Ready((self.inner.into_inner(), data.to_vec())))
    }
}

pub struct UnencryptedWritePacket<W: Write> {
    inner: Option<AsyncBufWriter<W>>,
    payload: Vec<u8>,
    padding: Vec<u8>,
    wr_state: WriteState,
}

enum WriteState {
    BeforeHeader,
    BeforePayload,
    BeforePadding
}

impl <W: Write> Future for UnencryptedWritePacket<W> {
    type Item = AsyncBufWriter<W>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<AsyncBufWriter<W>, io::Error> {
        match self.wr_state {
            WriteState::BeforeHeader => {
                let pkt_len = self.payload.len() + self.padding.len() + 1;
                let mut header = [0u8; 5];
                header[0] = (pkt_len >> 24) as u8;
                header[1] = (pkt_len >> 16) as u8;
                header[2] = (pkt_len >> 8) as u8;
                header[3] = pkt_len as u8;
                header[4] = self.padding.len() as u8;
                match try!(self.inner.as_mut().unwrap().nb_write_exact(&header)) {
                    Async::NotReady => Ok(Async::NotReady),
                    Async::Ready(()) => {
                        self.wr_state = WriteState::BeforePayload;
                        self.poll()
                    }
                }
            },
            WriteState::BeforePayload => {
                match try!(self.inner.as_mut().unwrap().nb_write_exact(&self.payload)) {
                    Async::NotReady => Ok(Async::NotReady),
                    Async::Ready(()) => {
                        self.wr_state = WriteState::BeforePadding;
                        self.poll()
                    }
                }
            },
            WriteState::BeforePadding => {
                match try!(self.inner.as_mut().unwrap().nb_write_exact(&self.padding)) {
                    Async::NotReady => Ok(Async::NotReady),
                    Async::Ready(()) => Ok(Async::Ready(self.inner.take().unwrap()))
                }
            }
        }
    }
}

pub fn unencrypted_write_packet<W: Write, R: Rng>(sink: AsyncBufWriter<W>, payload: Vec<u8>, rng: &mut R) -> UnencryptedWritePacket<W> {
    let pad_len = 16 - ((payload.len() + 5) % 8);
    let mut padding = vec![0u8; pad_len];
    rng.fill_bytes(&mut padding);

    UnencryptedWritePacket {
        inner: Some(sink),
        payload: payload,
        padding: padding,
        wr_state: WriteState::BeforeHeader
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use async::bufwriter::AsyncBufWriter;
    use futures::{Async, Future};
    use rand::thread_rng;

    #[test]
    fn test_unencrypted_write_packet() {
        let writer = Vec::new();
        let bufwriter = AsyncBufWriter::new(writer);
        let mut rng = thread_rng();
        if let Async::Ready(bufwritten) = unencrypted_write_packet(bufwriter, b"test".as_ref().to_owned(), &mut rng).poll().unwrap() {
            if let Async::Ready(written) = bufwritten.nb_into_inner().unwrap() {
                assert_eq!(4, ntoh(&written.as_slice()[.. 4]) % 8);
            } else {
                panic!("Async::NotReady");
            }
        } else {
            panic!("cannot unwrap bufwriter");
        }
    }

    #[test]
    fn test_unencrypted_write_packet_2() {
        let writer = Vec::new();
        let bufwriter = AsyncBufWriter::new(writer);
        let mut rng = thread_rng();
        if let Async::Ready(bufwritten) = unencrypted_write_packet(bufwriter, b"test2".as_ref().to_owned(), &mut rng).poll().unwrap() {
            if let Async::Ready(written) = bufwritten.nb_into_inner().unwrap() {
                assert_eq!(4, ntoh(&written.as_slice()[.. 4]) % 8);
            } else {
                panic!("Async::NotReady");
            }
        } else {
            panic!("cannot unwrap bufwriter");
        }
    }
}
