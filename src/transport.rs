use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;

use std::{cmp, io};
use std::io::{Read, Write};

use futures::{Async, Future, Poll};
use rand::{Rng, thread_rng};

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

pub struct PacketWriteRequest {
    pub payload: Vec<u8>,
    pub flush: bool
}

pub trait AsyncPacketState: Future {
    fn wants_read(&self) -> bool {
        false
    }

    fn on_read(&mut self, _msg: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_packet(&self) -> Option<PacketWriteRequest> {
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

pub struct AsyncPacketTransport<R: Read, W: Write, RNG, T> {
    rd: AsyncBufReader<R>,
    rd_st: PacketReadState,
    wr: AsyncBufWriter<W>,
    wr_st: PacketWriteState,
    rng: RNG,
    st: T,
}

impl <R: Read, W: Write, RNG, T> AsyncPacketTransport<R, W, RNG, T> {
    pub fn new(rd: AsyncBufReader<R>,
               wr: AsyncBufWriter<W>,
               rng: RNG,
               st: T) -> AsyncPacketTransport<R, W, RNG, T>
    {
        AsyncPacketTransport {
            rd: rd,
            rd_st: PacketReadState::Idle,
            wr: wr,
            wr_st: PacketWriteState::Idle,
            rng: rng,
            st: st
        }
    }
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
    let pkt_upperbound = cmp::min(try_add!(payload_len, 5 + 255), try_add!(::std::u32::MAX as usize, 4));

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
        let pkt_len = try_add!(pad_len, except_pad) - 4;
        Ok((pkt_len as u32, pad_len as u8))
    } else {
        Err(())
    }
}

impl <R, W, RNG, T> AsyncPacketTransport<R, W, RNG, T>
    where R: Read, W: Write, RNG: Rng, T: AsyncPacketState, T::Error: TransportError
{
    fn try_write(&mut self) -> Result<(), T::Error> {
        let next_state = match self.wr_st {
            PacketWriteState::Idle => {
                if let Some(req) = self.st.write_packet() {
                    let (pkt_len, pad_len) = try!(compute_pad_len(req.payload.len(), 0, &mut self.rng));
                    PacketWriteState::WritePayload(req, pkt_len, pad_len)
                } else {
                    return Ok(());
                }
            },
            PacketWriteState::WritePayload(ref req, pkt_len, pad_len) => {
                if pkt_len as usize != req.payload.len() + 1 + pad_len as usize {
                    return Err(T::Error::panic("pkt_len does not match"));
                }

                let async_res = try!(self.wr.nb_write(pkt_len as usize + 4, |buf| {
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
        self.try_write()
    }

    fn try_read(&mut self) -> Result<(), T::Error> {
        let next_state = match self.rd_st {
            PacketReadState::Idle => {
                if !self.st.wants_read() {
                    return Ok(());
                }

                if let Async::Ready(buf) = try!(self.rd.nb_read_exact(5)) {
                    let pkt_len = ntoh(&buf[.. 4]);
                    let pad_len = buf[4];
                    if pkt_len < 16 || pkt_len < (pad_len as u32) + 1 {
                        return Err(T::Error::invalid_header());
                    }
                    PacketReadState::ReadPayload(pkt_len, pad_len)
                } else {
                    return Ok(());
                }
            },
            PacketReadState::ReadPayload(pkt_len, pad_len) => {
                if let Async::Ready(buf) = try!(self.rd.nb_read_exact(pkt_len as usize - 1)) {
                    let payload_len = pkt_len as usize - pad_len as usize - 1;
                    try!(self.st.on_read(&buf[..payload_len]));
                    PacketReadState::Idle
                } else {
                    return Ok(());
                }
            }
        };

        self.rd_st = next_state;
        self.try_read()
    }
}

impl <R, W, RNG, T, V, E> Future for AsyncPacketTransport<R, W, RNG, T>
    where R: Read, W: Write, RNG: Rng, T: AsyncPacketState + Future<Item=Option<V>, Error=E>, E: TransportError
{
    type Item = V;
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        try!(self.try_write());
        try!(self.try_read());

        match try!(self.st.poll()) {
            Async::Ready(None) => self.poll(),
            Async::Ready(Some(x)) => Ok(Async::Ready(x)),
            Async::NotReady => Ok(Async::NotReady)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_compute_pad_len() {
        let mut rng = thread_rng();
        for payload_len in 1 .. 257 {
            if let Ok((pkt_len, pad_len)) = compute_pad_len(payload_len, 0, &mut rng) {
                assert_eq!(pkt_len % 8, 4);
                assert_eq!(pkt_len as usize, pad_len as usize + payload_len + 1);
            } else {
                panic!("compute_pad_len failed at payload_len = {}", payload_len);
            }
        }
    }
}
