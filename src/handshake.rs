use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use key::KeyBuilder;
use packet::types::{AlgorithmNegotiation, KexInit, KexReply, ServerKey, Signature};
use packet::{deserialize, deserialize_msg, serialize, serialize_msg};
use transport::{unencrypted_read_packet, unencrypted_write_packet, ntoh};

use std::{fmt, io, str};
use std::io::{Read, Write};
use futures::{Async, Future, Poll};
use rand::Rng;
use ring::{agreement, digest, rand, signature};
use ring::digest::Context;
use tokio_core::io::{flush, read_until, write_all};
use untrusted;

use ::{SSH_MSG_KEXINIT, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY};

#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    InvalidVersionExchange,
    InvalidAlgorithmNegotiation(String),
    InvalidKexReply(String),
    KexFailed,
    ServerKeyNotVerified,
    UnknownCertType(String)
}

pub struct SshContext {
    session_id: Vec<u8>
}

pub struct PacketWriteRequest {
    msg_id: u8,
    payload: Vec<u8>,
    flush: bool
}

pub trait AsyncPacketState: Future {
    fn wants_read(&self) -> bool {
        false
    }

    fn on_read(&mut self, msg_id: u8, msg: &[u8]) -> Result<(), Self::Error> {
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
    WriteHeader,
    WritePayload,
    WritePadding,
    Flush
}

pub struct AsyncPacketTransport<'r, 'w, R: Read+'r, W: Write+'w, RNG, T> {
    rd: &'r mut AsyncBufReader<R>,
    rd_st: PacketReadState,
    wr: &'w mut AsyncBufWriter<W>,
    wr_req: Option<PacketWriteRequest>,
    wr_st: PacketWriteState,
    rng: RNG,
    st: T,
}

pub trait TransportError : From<io::Error> {
    fn invalid_header() -> Self;
}

impl <'r, 'w, R, W, RNG, T> Future for AsyncPacketTransport<'r, 'w, R, W, RNG, T>
    where R: Read + 'r, W: Write + 'w, RNG: Rng, T: AsyncPacketState, T::Error: TransportError
{
    type Item = T::Item;
    type Error = T::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.rd_st {
            PacketReadState::Idle => {
                if self.st.wants_read() {
                    if let Async::Ready(buf) = try!(self.rd.nb_read_exact(5)) {
                        let pkt_len = ntoh(&buf[.. 4]);
                        let pad_len = buf[4];
                        if pkt_len < 16 || pkt_len < (pad_len as u32) + 1 {
                            return Err(Self::Error::invalid_header());
                        }
                        self.rd_st = PacketReadState::ReadPayload(pkt_len, pad_len);
                    }
                }
            },
            PacketReadState::ReadPayload(pkt_len, pad_len) => {
                if let Async::Ready(buf) = try!(self.rd.nb_read_exact(pkt_len as usize - 1)) {
                    self.rd_st = PacketReadState::Idle;
                    try!(self.st.on_read(buf[0], &buf[1..]));
                }
            }
        }

        match self.wr_req {
            None => {
                if let Some(req) = match self.st.wants_write() {
                    self.wr_req = req;
                }
            },
            Some(ref req) => {
                match self.wr_st {
                    PacketWriteState::WriteHeader {
                        let pkt_len = self.payload.len() + self.padding.len() + 1;
                        let mut header = [0u8; 5];
                        header[0] = (pkt_len >> 24) as u8;
                        header[1] = (pkt_len >> 16) as u8;
                        header[2] = (pkt_len >> 8) as u8;
                        header[3] = pkt_len as u8;
                        header[4] = self.padding.len() as u8;
                        if let Async::Ready(()) = try!(self.wr.nb_write_exact(&header)) {
                            self.wr_st = PacketWriteState::WritePayload;
                        }
                    },
                    PacketWriteState::WritePayload {
                        if let Async::Ready(()) = try!(self.wr.nb_write_exact(&req.payload)) {
                            self.wr_st = PacketWriteState::WritePadding;
                        }
                    },
                    PacketWriteState::WritePadding {
                        if let Async::Ready(()) = try!(self.wr.nb_write_exact(&req.padding)) {
                            self.wr_st = PacketWriteState::WritePadding;
                        }
                    },
                }
            }
        } 

        Ok(Async::NotReady)
    }
}

pub struct ClientHandshake<'r, 'w, R: Read + 'r, W: Write + 'w> {
    rd: &'r mut AsyncBufReader<R>,
    wr: &'w mut AsyncBufWriter<W>,
    st: ClientKeyExchange
}

impl Future for ClientKeyExchange {
    type Item = SshContext;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::NotReady)
    }
}

struct ClientKeyExchange {
    v_c: String,
    v_s: String,
    st: ClientKexState
}

enum ClientKexState {
    AlgorithmExchange(AlgorithmExchangeState),
    KeyExchange(KeyExchangeState),
    Done(SshContext)
}

struct AlgorithmExchangeState {
    i_c: Vec<u8>,
    w_st: PacketWriteState,
    r_st: PacketReadState
}

struct KeyExchangeState {
    e: Vec<u8>,
    hash_ctx: Context,
    w_st: PacketWriteState,
    r_st: PacketReadState
}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> HandshakeError {
        HandshakeError::IoError(e)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::IoError(ref e) =>
                e.fmt(f),
            HandshakeError::InvalidVersionExchange =>
                write!(f, "InvalidVersionExchange"),
            HandshakeError::InvalidAlgorithmNegotiation(ref msg) =>
                write!(f, "InvalidAlgorithmNegotiation({})", msg),
            HandshakeError::InvalidKexReply(ref msg) =>
                write!(f, "InvalidKexReply({})", msg),
            HandshakeError::KexFailed =>
                write!(f, "KexFailed"),
            HandshakeError::ServerKeyNotVerified =>
                write!(f, "ServerKeyNotVerified"),
            HandshakeError::UnknownCertType(ref s) =>
                write!(f, "UnknownCertType({})", s)
        }
    }
}

pub fn build_kexinit_payload(neg: &AlgorithmNegotiation, rng: &mut Rng) -> Result<Vec<u8>, HandshakeError> {
    let kexinit = serialize(neg).unwrap();
    let mut payload = Vec::new();
    try!(payload.write(&[SSH_MSG_KEXINIT]));
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    try!(payload.write(&cookie));
    try!(payload.write(&kexinit));

    Ok(payload)
}

pub fn version_exchange<R, W>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, version_string: &str, comment: &str)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, KeyBuilder), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    let v_c = format!("SSH-2.0-{} {}", version_string, comment);

    let mut buf = Vec::with_capacity(256);
    buf.write(v_c.as_bytes()).unwrap();
    buf.write(b"\r\n").unwrap();
    println!("V_C: SSH-2.0-{} {}", version_string, comment);
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    let w = write_all(writer, buf).and_then(|(writer, _)| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = read_until(reader, b'\n', Vec::with_capacity(256)).map_err(|e| e.into()).and_then(|(reader, buf)| {
        if buf.starts_with(b"SSH-2.0-") && buf.ends_with(b"\r\n") {
            match str::from_utf8(&buf[.. buf.len() - 2]) {
                Ok(v_s) => {
                    let keybuilder = KeyBuilder {
                        v_c: Some(v_c),
                        v_s: Some(v_s.into()),
                        .. Default::default()
                    };
                    Ok((reader, keybuilder))
                },
                Err(_) => Err(HandshakeError::InvalidVersionExchange)
            }
        } else {
            Err(HandshakeError::InvalidVersionExchange)
        }
    });

    w.join(r).map(|(writer, (reader, keybuilder))| (reader, writer, keybuilder)).boxed()
}

pub fn algorithm_negotiation<R, W, RNG>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, supported_algorithms: &AlgorithmNegotiation, rng: &mut RNG, mut keybuilder: KeyBuilder)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, AlgorithmNegotiation, KeyBuilder), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static, RNG: Rng
{
    let payload = build_kexinit_payload(supported_algorithms, rng).unwrap();
    keybuilder.i_c = Some(payload.clone());

    let w = unencrypted_write_packet(writer, payload, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());

    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, buf)| {
        if buf[0] == SSH_MSG_KEXINIT {
            keybuilder.i_s = Some(buf.clone());
            match deserialize::<AlgorithmNegotiation>(&buf[17..]) {
                Ok(neg) => Ok((reader, neg, keybuilder)),
                Err(e) => Err(HandshakeError::InvalidAlgorithmNegotiation(e.to_string()))
            }
        } else {
            Err(HandshakeError::InvalidAlgorithmNegotiation("SSH_MSG_KEXINIT not received".to_string()))
        }
    });

    w.join(r).map(|(writer, (reader, packet, kb))| (reader, writer, packet, kb)).boxed()
}

pub fn ecdh_sha2_nistp256_server<R, W>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, Vec<u8>), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    unencrypted_read_packet(reader).map_err(|e| e.into()).map(|(reader, buf)| {
        (reader, writer, buf)
    }).boxed()
}

fn into_mpint(buf: &[u8]) -> Vec<u8> {
    if buf.len() == 0 {
        Vec::new()
    } else if buf[0] <= 0x7f {
        buf.into()
    } else {
        let mut v = Vec::with_capacity(buf.len() + 1);
        v.push(0);
        v.extend_from_slice(buf);
        v
    }
}

fn from_mpint(data: &[u8]) -> &[u8] {
    if data.len() > 0 && data[0] == 0 {
        &data[1..]
    } else {
        data
    }
}

pub fn ecdh_curve25519_client<R, W, RNG>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, rng: &mut RNG, mut keybuilder: KeyBuilder)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, KeyBuilder), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static, RNG: Rng
{
    let ring_rng = rand::SystemRandom::new();
    let client_priv_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &ring_rng).unwrap();
    let mut key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
    client_priv_key.compute_public_key(&mut key[..client_priv_key.public_key_len()]).unwrap();
    let client_pub_key = &key[..client_priv_key.public_key_len()];
    keybuilder.e = Some(client_pub_key.to_vec());

    let kex_init = KexInit { e: client_pub_key.to_vec() };
    let kex_message = serialize_msg(SSH_MSG_KEXDH_INIT, &kex_init).unwrap();

    let w = unencrypted_write_packet(writer, kex_message, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, payload)| {
        match deserialize_msg::<KexReply>(&payload) {
            Ok((msg_key, reply)) => if msg_key == SSH_MSG_KEXDH_REPLY {
                let pub_key = {
                    let &ServerKey::SSH_RSA { ref e, ref n } = &reply.server_key;
                    (
                        untrusted::Input::from(from_mpint(n)),
                        untrusted::Input::from(from_mpint(e))
                    )
                };
                keybuilder.k_s = Some(serialize(&reply.server_key).unwrap());
                keybuilder.server_key = Some(reply.server_key.clone());
                keybuilder.f = Some(reply.f.clone());
                let server_pub_key = untrusted::Input::from(&reply.f);
                agreement::agree_ephemeral(client_priv_key, &agreement::X25519, server_pub_key, HandshakeError::KexFailed, |shared_secret| {
                    keybuilder.k = Some(into_mpint(shared_secret));
                    Ok(())
                }).unwrap();
                let hash = keybuilder.digest(&digest::SHA256).unwrap();
                let h = untrusted::Input::from(&hash.as_ref());
                let Signature::SSH_RSA { signature: ref sgn } = reply.signature;
                let sgn = untrusted::Input::from(sgn);
                match signature::primitive::verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA1,
                                               pub_key, h, sgn) {
                    Ok(()) => Ok((reader, keybuilder)),
                    Err(_) => Err(HandshakeError::ServerKeyNotVerified)
                }
            } else {
                Err(HandshakeError::InvalidKexReply("SSH_MSG_KEXDH_REPLY not received".to_string()))
            },
            Err(e) => Err(HandshakeError::InvalidKexReply(e.to_string()))
        }
    });

    w.join(r).map(|(writer, (reader, keybuilder))| (reader, writer, keybuilder)).boxed()
}
