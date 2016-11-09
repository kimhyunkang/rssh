use buffered_io::BufferedIo;

use std::{io, mem, str};

use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::io::Io;

pub fn take_stream<S: Stream>(stream: S, len: usize) -> TakeStream<S> {
    TakeStream {
        state: Some( TakeStreamState { inner: stream, buf: Vec::with_capacity(len) } ), 
        len: len
    }
}

pub struct TakeStream<S> where S: Stream {
    state: Option<TakeStreamState<S>>,
    len: usize
}

pub struct TakeStreamState<S> where S: Stream {
    inner: S,
    buf: Vec<S::Item>
}

impl <S: Stream> Future for TakeStream<S> {
    type Item = (S, Vec<S::Item>);
    type Error = S::Error;

    fn poll(&mut self) -> Poll<(S, Vec<S::Item>), S::Error> {
        let end_of_stream = match self.state {
            Some(ref mut st) => {
                match st.inner.poll() {
                    Ok(Async::Ready(Some(x))) => {
                        st.buf.push(x);
                        st.buf.len() >= self.len
                    },
                    Ok(Async::Ready(None)) => {
                        true
                    },
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    },
                    Err(e) => {
                        return Err(e);
                    }
                }
            },
            None => panic!("Tried to take from depleted stream")
        };

        if end_of_stream {
            match mem::replace(&mut self.state, None) {
                Some( TakeStreamState { inner, buf } ) =>
                    Ok(Async::Ready((inner, buf))),
                None => unreachable!()
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

pub struct NamedListParser<S: Io> {
    inner: BufferedIo<S>,
    header: Option<u32>
}

impl <S: Io> NamedListParser<S> {
    pub fn new(inner: BufferedIo<S>) -> NamedListParser<S> {
        NamedListParser {
            inner: inner,
            header: None
        }
    }

    pub fn into_inner(self) -> BufferedIo<S> {
        self.inner
    }
}

fn ntoh(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) + ((buf[1] as u32) << 16) + ((buf[2] as u32) << 8) + (buf[3] as u32)
}

impl <S: Io> Stream for NamedListParser<S>
{
    type Item = Vec<String>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Vec<String>>, io::Error> {
        match self.header {
            None => {
                match try!(self.inner.nb_read_exact(4)) {
                    None => return Ok(Async::NotReady),
                    Some(buf) => {
                        self.header = Some(ntoh(buf));
                    }
                };
                self.poll()
            },
            Some(n) => match try!(self.inner.nb_read_exact(n as usize)) {
                None => Ok(Async::NotReady),
                Some(buf) => {
                    self.header = None;
                    match str::from_utf8(buf) {
                        Ok(list) => {
                            let ret: Vec<String> = list.split(',').map(|s| s.to_owned()).collect();
                            Ok(Async::Ready(Some(ret)))
                        },
                        Err(_) => 
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Non-ASCII string in name-list"
                            ))
                    }
                }
            }
        }
    }
}

pub struct UnencryptedStream<S: Io> {
    inner: BufferedIo<S>,
    rd_header: Option<(usize, usize)>
}

impl <S: Io> UnencryptedStream<S> {
    pub fn nb_read_packet<'r>(&'r mut self) -> Poll<&'r [u8], io::Error> {
        match self.rd_header {
            None => {
                match try!(self.inner.nb_read_exact(5)) {
                    None => return Ok(Async::NotReady),
                    Some(buf) => {
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
            Some((pkt_len, pad_len)) => match try!(self.inner.nb_read_exact(pkt_len - 1)) {
                None => Ok(Async::NotReady),
                Some(buf) => {
                    self.rd_header = None;
                    Ok(Async::Ready(&buf[.. pkt_len - pad_len - 1]))
                }
            }
        }
    }
}
