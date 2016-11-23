use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;

use std::{cmp, io};
use std::io::{Read, Write};

use futures::{Async, Future, Poll};
use rand::{Rng, thread_rng};

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

pub struct PacketWriteRequest {
    pub payload: Vec<u8>,
    pub flush: bool
}

pub trait AsyncPacketState: Future {
    fn wants_read(&self) -> bool {
        false
    }

    fn on_read(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn wants_write(&self) -> Option<PacketWriteRequest> {
        None
    }

    fn on_flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

enum PacketReadState {
    Idle,
    ReadPayload(u32, u8),
}

enum PacketWriteState {
    Idle,
    WritePayload(PacketWriteRequest, u32, u8),
    Flush
}

pub struct AsyncPacketTransport<'r, 'w, R: Read+'r, W: Write+'w, RNG, T> {
    rd: &'r mut AsyncBufReader<R>,
    rd_st: PacketReadState,
    wr: &'w mut AsyncBufWriter<W>,
    wr_st: PacketWriteState,
    rng: RNG,
    st: T,
}

pub trait TransportError : From<io::Error> + From<()> {
    fn invalid_header() -> Self;
    fn panic(&'static str) -> Self;
}

macro_rules! try_add {
    ($a:expr, $b:expr) => {
        if let Some(x) = $a.checked_add($b) {
            x
        } else {
            return Err(().into());
        }
    }
}

macro_rules! try_sub {
    ($a:expr, $b:expr) => {
        if let Some(x) = $a.checked_sub($b) {
            x
        } else {
            return Err(().into());
        }
    }
}

pub fn compute_pad_len<R: Rng>(payload_len: usize, blk_size: usize, rng: &mut R) -> Result<(u32, u8), ()> {
    let min_unit = cmp::max(blk_size, 8);

    // maximum possible pkt_len = 5 byte header + payload_len + 255
    let pkt_upperbound = cmp::min(try_add!(payload_len, 5 + 255), ::std::u32::MAX as usize);

    // pkt_len = 5 byte header + payload_len + pad_len
    // pad_len must be 4 bytes or larger
    // pkt_len must be 16 bytes or larger, and it must be multiple of max(blk_size, 8)
    let pkt_lowerbound = cmp::max(try_add!(payload_len, 5 + 4), cmp::max(min_unit, 16));

    let max_pkt_len = pkt_upperbound - (pkt_upperbound % min_unit);
    let min_pkt_len = try_add!(pkt_lowerbound, min_unit - 1) / min_unit * min_unit;

    let except_pad = try_add!(payload_len, 5);
    let max_pad_len = try_sub!(max_pkt_len, except_pad);
    let min_pad_len = try_sub!(min_pkt_len, except_pad);

    if 4 <= min_pad_len && min_pad_len <= max_pad_len && max_pad_len <= 255 {
        let pad_len = 
            rng.gen_range(0, (max_pad_len - min_pad_len) / min_unit + 1) * min_unit + min_pad_len;
        let pkt_len = try_add!(pad_len, except_pad);
        Ok((pkt_len as u32, pad_len as u8))
    } else {
        Err(())
    }
}

impl <'r, 'w, R, W, RNG, T> AsyncPacketTransport<'r, 'w, R, W, RNG, T>
    where R: Read + 'r, W: Write + 'w, RNG: Rng, T: AsyncPacketState, T::Error: TransportError
{
    fn try_write(&mut self) -> Result<(), T::Error> {
        let next_state = match self.wr_st {
            PacketWriteState::Idle => {
                if let Some(req) = self.st.wants_write() {
                    let (pkt_len, pad_len) = try!(compute_pad_len(req.payload.len(), 0, &mut self.rng));
                    PacketWriteState::WritePayload(req, pkt_len, pad_len)
                } else {
                    return Ok(());
                }
            },
            PacketWriteState::WritePayload(ref req, pkt_len, pad_len) => {
                if pkt_len as usize != req.payload.len() + 6 + pad_len as usize {
                    return Err(T::Error::panic("pkt_len does not match"));
                }

                let async_res = try!(self.wr.nb_write(pkt_len as usize, |buf| {
                    buf[0] = ((pkt_len >> 24) & 0xff) as u8;
                    buf[1] = ((pkt_len >> 16) & 0xff) as u8;
                    buf[2] = ((pkt_len >> 8) & 0xff) as u8;
                    buf[3] = (pkt_len & 0xff) as u8;
                    buf[4] = pad_len;
                    buf[5 .. 5 + req.payload.len()].copy_from_slice(&req.payload);

                    let mut rng = thread_rng();
                    rng.fill_bytes(&mut buf[5 + req.payload.len() ..]);
                }));

                if let Async::NotReady = async_res {
                    return Ok(());
                } else if req.flush {
                    PacketWriteState::Flush
                } else {
                    try!(self.st.on_flush());
                    PacketWriteState::Idle
                }
            },
            PacketWriteState::Flush => {
                if let Async::Ready(()) = try!(self.wr.nb_flush()) {
                    try!(self.st.on_flush());
                    PacketWriteState::Idle
                } else {
                    return Ok(());
                }
            }
        };

        self.wr_st = next_state;
        Ok(())
    }

    fn try_read(&mut self) -> Result<(), T::Error> {
        match self.rd_st {
            PacketReadState::Idle => {
                if self.st.wants_read() {
                    if let Async::Ready(buf) = try!(self.rd.nb_read_exact(5)) {
                        let pkt_len = ntoh(&buf[.. 4]);
                        let pad_len = buf[4];
                        if pkt_len < 16 || pkt_len < (pad_len as u32) + 1 {
                            return Err(T::Error::invalid_header());
                        }
                        self.rd_st = PacketReadState::ReadPayload(pkt_len, pad_len);
                    }
                }
            },
            PacketReadState::ReadPayload(pkt_len, pad_len) => {
                if let Async::Ready(buf) = try!(self.rd.nb_read_exact(pkt_len as usize - 1)) {
                    let payload_len = pkt_len as usize - pad_len as usize - 1;
                    self.rd_st = PacketReadState::Idle;
                    try!(self.st.on_read(buf));
                }
            }
        }

        Ok(())
    }
}

impl <'r, 'w, R, W, RNG, T> Future for AsyncPacketTransport<'r, 'w, R, W, RNG, T>
    where R: Read + 'r, W: Write + 'w, RNG: Rng, T: AsyncPacketState, T::Error: TransportError
{
    type Item = T::Item;
    type Error = T::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        try!(self.try_write());
        try!(self.try_read());

        self.st.poll()
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

    #[test]
    fn test_compute_pad_len() {
        let mut rng = thread_rng();
        for payload_len in 1 .. 257 {
            if let Ok((pkt_len, pad_len)) = compute_pad_len(payload_len, 0, &mut rng) {
                assert_eq!(pkt_len % 8, 0);
                assert_eq!(pkt_len as usize, pad_len as usize + payload_len + 5);
            } else {
                panic!("compute_pad_len failed at payload_len = {}", payload_len);
            }
        }
    }
}
