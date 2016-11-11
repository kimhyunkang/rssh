use async::bufreader::AsyncBufReader;

use std::io;
use std::io::Read;

use futures::{Async, Future, Poll};

pub struct UnencryptedStream<R: Read> {
    inner: Option<AsyncBufReader<R>>,
    rd_header: Option<(usize, usize)>
}

fn ntoh(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) + ((buf[1] as u32) << 16) + ((buf[2] as u32) << 8) + (buf[3] as u32)
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
                        let pad_len = buf[5] as usize;
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
