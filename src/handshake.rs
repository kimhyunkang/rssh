use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use packet::types::*;
use packet::{deserialize, serialize, serialize_msg};
use transport::{AsyncPacketState, AsyncPacketTransport, PacketWriteRequest, TransportError, hton};

use std::{fmt, io, str};
use std::convert::TryFrom;
use std::io::{Read, Write};
use futures::{Async, Future, Poll};
use rand::{OsRng, Rng};
use ring::{agreement, digest, rand, signature};
use ring::digest::Context;
use tokio_core::io::{flush, read_until, write_all};
use untrusted;

use ::{SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY};

#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    InvalidHeader,
    InvalidVersionExchange,
    InvalidAlgorithmNegotiation(String),
    InvalidKexReply(String),
    KexFailed,
    ServerKeyNotVerified,
    UnknownCertType(String),
    Unspecified,
    Panic(String)
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
            HandshakeError::InvalidHeader =>
                write!(f, "InvalidHeader"),
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
                write!(f, "UnknownCertType({})", s),
            HandshakeError::Unspecified =>
                write!(f, "Unspecified"),
            HandshakeError::Panic(ref s) =>
                write!(f, "Panic({})", s)
        }
    }
}

impl From<()> for HandshakeError {
    fn from(_: ()) -> HandshakeError {
        HandshakeError::Unspecified
    }
}

impl TransportError for HandshakeError {
    fn invalid_header() -> HandshakeError {
        HandshakeError::InvalidHeader
    }

    fn panic(msg: &'static str) -> HandshakeError {
        HandshakeError::Panic(msg.into())
    }
}

#[derive(Clone, Debug)]
pub struct NegotiatedAlgorithm {
    pub kex_algorithms: KexAlgorithm,
    pub server_host_key_algorithms: ServerHostKeyAlgorithm,
    pub encryption_algorithms_client_to_server: EncryptionAlgorithm,
    pub encryption_algorithms_server_to_client: EncryptionAlgorithm,
    pub mac_algorithms_client_to_server: MacAlgorithm,
    pub mac_algorithms_server_to_client: MacAlgorithm,
    pub compression_algorithms_client_to_server: CompressionAlgorithm,
    pub compression_algorithms_server_to_client: CompressionAlgorithm,
    pub languages_client_to_server: Option<Language>,
    pub languages_server_to_client: Option<Language>
}

#[derive(Debug)]
pub struct SecureContext {
    neg_algorithm: NegotiatedAlgorithm,
    session_id: Vec<u8>
}

pub struct ClientKeyExchange {
    st: ClientKex
}

pub enum ClientKex {
    AlgorithmExchange(AlgorithmExchangeState),
    KeyExchange(KeyExchangeState),
    Agreed(Agreed)
}

impl Future for ClientKeyExchange {
    type Item = Option<SecureContext>;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<Option<SecureContext>, HandshakeError> {
        let next_st = match self.st {
            ClientKex::AlgorithmExchange(ref mut st) => {
                if let Async::Ready(kex) = try!(st.poll()) {
                    ClientKex::KeyExchange(kex)
                } else {
                    return Ok(Async::NotReady);
                }
            },
            ClientKex::KeyExchange(ref mut st) => {
                if let Async::Ready(agreed) = try!(st.poll()) {
                    ClientKex::Agreed(agreed)
                } else {
                    return Ok(Async::NotReady);
                }
            },
            ClientKex::Agreed(ref mut st) => match try!(st.poll()) {
                Async::Ready(ctx) => return Ok(Async::Ready(Some(ctx))),
                Async::NotReady => return Ok(Async::NotReady)
            }
        };

        self.st = next_st;
        Ok(Async::Ready(None))
    }
}

impl AsyncPacketState for ClientKeyExchange {
    fn wants_read(&self) -> bool {
        match self.st {
            ClientKex::AlgorithmExchange(ref st) => st.wants_read(),
            ClientKex::KeyExchange(ref st) => st.wants_read(),
            ClientKex::Agreed(_) => false,
        }
    }

    fn on_read(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        match self.st {
            ClientKex::AlgorithmExchange(ref mut st) => st.on_read(msg),
            ClientKex::KeyExchange(ref mut st) => st.on_read(msg),
            ClientKex::Agreed(_) => unreachable!()
        }
    }

    fn write_packet(&self) -> Option<PacketWriteRequest> {
        match self.st {
            ClientKex::AlgorithmExchange(ref st) => st.write_packet(),
            ClientKex::KeyExchange(ref st) => st.write_packet(),
            ClientKex::Agreed(ref st) => st.write_packet(),
        }
    }

    fn on_flush(&mut self) -> Result<(), Self::Error> {
        match self.st {
            ClientKex::AlgorithmExchange(ref mut st) => st.on_flush(),
            ClientKex::KeyExchange(ref mut st) => st.on_flush(),
            ClientKex::Agreed(ref mut st) => st.on_flush(),
        }
    }
}

pub struct AlgorithmExchangeState {
    v_c: String,
    v_s: String,
    i_c: Vec<u8>,
    written: bool,
    res: Option<(NegotiatedAlgorithm, Context)>
}

fn digest_bytes(ctx: &mut Context, bytes: &[u8]) -> Result<(), HandshakeError> {
    let len: u32 = match TryFrom::try_from(bytes.len()) {
        Ok(l) => l,
        Err(_) => return Err(HandshakeError::KexFailed)
    };

    ctx.update(&hton(len));
    ctx.update(bytes);
    Ok(())
}

impl Future for AlgorithmExchangeState {
    type Item = KeyExchangeState;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<KeyExchangeState, HandshakeError> {
        match self.res.take() {
            Some((neg, ctx)) => {
                let ring_rng = rand::SystemRandom::new();
                let keygen = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &ring_rng);
                if let Ok(priv_key) = keygen {
                    let mut key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
                    priv_key.compute_public_key(&mut key[..priv_key.public_key_len()]).unwrap();
                    let pub_key = &key[..priv_key.public_key_len()];
                    Ok(Async::Ready(KeyExchangeState {
                        neg: neg,
                        keyshare: Some((ctx, priv_key)),
                        e: pub_key.to_vec(),
                        written: false,
                        res: None
                    }))
                } else {
                    Err(HandshakeError::KexFailed)
                }
            }
            None => Ok(Async::NotReady)
        }
    }
}

impl AsyncPacketState for AlgorithmExchangeState {
    fn wants_read(&self) -> bool {
        self.res.is_none()
    }

    fn on_read(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if msg.len() == 0 || msg[0] != SSH_MSG_KEXINIT {
            return Err(HandshakeError::InvalidAlgorithmNegotiation(
                    "SSH_MSG_KEXINIT not received".to_string()
            ));
        }

        match deserialize::<AlgorithmNegotiation>(&msg[17..]) {
            Err(e) => Err(HandshakeError::InvalidAlgorithmNegotiation(e.to_string())),
            Ok(_neg) => {
                // XXX: Actually implement algorithm implementation
                let algorithms = NegotiatedAlgorithm {
                    kex_algorithms: KexAlgorithm::CURVE25519_SHA256,
                    server_host_key_algorithms: ServerHostKeyAlgorithm::SSH_RSA,
                    encryption_algorithms_client_to_server: EncryptionAlgorithm::AES256_GCM,
                    encryption_algorithms_server_to_client: EncryptionAlgorithm::AES256_GCM,
                    mac_algorithms_client_to_server: MacAlgorithm::HMAC_SHA2_256,
                    mac_algorithms_server_to_client: MacAlgorithm::HMAC_SHA2_256,
                    compression_algorithms_client_to_server: CompressionAlgorithm::NONE,
                    compression_algorithms_server_to_client: CompressionAlgorithm::NONE,
                    languages_client_to_server: None,
                    languages_server_to_client: None
                };

                // XXX: Hash algorithm must be determined from NegotiatedAlgorithm
                let mut ctx = Context::new(&digest::SHA256);
                try!(digest_bytes(&mut ctx, self.v_c.as_bytes()));
                try!(digest_bytes(&mut ctx, self.v_s.as_bytes()));
                try!(digest_bytes(&mut ctx, &self.i_c));
                try!(digest_bytes(&mut ctx, msg));

                self.res = Some((algorithms, ctx));

                Ok(())
            }
        }
    }

    fn write_packet(&self) -> Option<PacketWriteRequest> {
        if self.written {
            None
        } else {
            Some(PacketWriteRequest {
                payload: self.i_c.clone(),
                flush: true
            })
        }
    }

    fn on_flush(&mut self) -> Result<(), HandshakeError> {
        self.written = true;
        Ok(())
    }
}

pub struct KeyExchangeState {
    neg: NegotiatedAlgorithm,
    keyshare: Option<(Context, agreement::EphemeralPrivateKey)>,
    e: Vec<u8>,
    written: bool,
    res: Option<Vec<u8>>
}

impl Future for KeyExchangeState {
    type Item = Agreed;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<Agreed, HandshakeError> {
        if !self.written {
            return Ok(Async::NotReady);
        }

        match self.res.take() {
            Some(session_id) => {
                let ssh_ctx = SecureContext {
                    neg_algorithm: self.neg.clone(),
                    session_id: session_id
                };
                Ok(Async::Ready(Agreed {
                    ctx: Some(ssh_ctx),
                    new_key_sent: false
                }))
            },
            None => Ok(Async::NotReady)
        }
    }
}

impl AsyncPacketState for KeyExchangeState {
    fn wants_read(&self) -> bool {
        self.res.is_none()
    }

    fn on_read(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if msg.len() == 0 || msg[0] != SSH_MSG_KEXDH_REPLY {
            return Err(HandshakeError::InvalidAlgorithmNegotiation(
                    "SSH_MSG_KEXDH_REPLY not received".to_string()
            ));
        }

        match deserialize::<KexReply>(&msg[1..]) {
            Err(e) => Err(HandshakeError::InvalidAlgorithmNegotiation(e.to_string())),
            Ok(reply) =>
                if let Some((mut hash_ctx, priv_key)) = self.keyshare.take() {
                    let pub_key = {
                        let &ServerKey::SSH_RSA { ref e, ref n } = &reply.server_key;
                        (
                            untrusted::Input::from(from_mpint(n)),
                            untrusted::Input::from(from_mpint(e))
                        )
                    };
                    let k_s = serialize(&reply.server_key).unwrap();
                    try!(digest_bytes(&mut hash_ctx, &k_s));
                    try!(digest_bytes(&mut hash_ctx, &self.e));
                    try!(digest_bytes(&mut hash_ctx, &reply.f));
                    let server_pub_key = untrusted::Input::from(&reply.f);
                    let k = try!(agreement::agree_ephemeral(priv_key,
                                                            &agreement::X25519,
                                                            server_pub_key,
                                                            HandshakeError::KexFailed,
                                                            |shared_secret| { Ok(into_mpint(shared_secret)) }
                    ));
                    try!(digest_bytes(&mut hash_ctx, &k));
                    let hash = hash_ctx.finish();
                    let h = untrusted::Input::from(&hash.as_ref());
                    let Signature::SSH_RSA { signature: ref sgn } = reply.signature;
                    let sgn = untrusted::Input::from(sgn);
                    match signature::primitive::verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA1,
                                                pub_key, h, sgn) {
                        Err(_) => {
                            Err(HandshakeError::ServerKeyNotVerified)
                        },
                        Ok(()) => {
                            self.res = Some(hash.as_ref().to_vec());
                            Ok(())
                        }
                    }
                } else {
                    panic!("Got key reply twice");
                }
        }
    }

    fn write_packet(&self) -> Option<PacketWriteRequest> {
        if self.written {
            None
        } else {
            let payload = serialize_msg(SSH_MSG_KEXDH_INIT, &KexInit { e: self.e.clone() }).unwrap();

            Some(PacketWriteRequest {
                payload: payload,
                flush: true
            })
        }
    }

    fn on_flush(&mut self) -> Result<(), HandshakeError> {
        self.written = true;
        Ok(())
    }
}

pub struct Agreed {
    ctx: Option<SecureContext>,
    new_key_sent: bool
}

impl Future for Agreed {
    type Item = SecureContext;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<SecureContext, HandshakeError> {
        if self.new_key_sent {
            match self.ctx.take() {
                Some(ctx) => Ok(Async::Ready(ctx)),
                None => panic!("Called Agreed::poll() twice")
            }
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl AsyncPacketState for Agreed {
    fn write_packet(&self) -> Option<PacketWriteRequest> {
        if self.new_key_sent {
            None
        } else {
            Some(PacketWriteRequest { payload: vec![SSH_MSG_NEWKEYS], flush: true })
        }
    }

    fn on_flush(&mut self) -> Result<(), Self::Error> {
        self.new_key_sent = true;
        Ok(())
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
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, (String, String)), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    let v_c = format!("SSH-2.0-{} {}", version_string, comment);

    let mut buf = Vec::with_capacity(256);
    buf.write(v_c.as_bytes()).unwrap();
    buf.write(b"\r\n").unwrap();
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
                    Ok((reader, (v_c, v_s.into())))
                },
                Err(_) => Err(HandshakeError::InvalidVersionExchange)
            }
        } else {
            Err(HandshakeError::InvalidVersionExchange)
        }
    });

    w.join(r).map(|(writer, (reader, pair))| (reader, writer, pair)).boxed()
}

pub fn client_key_exchange<R, W>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, neg: AlgorithmNegotiation, v_c: String, v_s: String)
        -> AsyncPacketTransport<R, W, OsRng, ClientKeyExchange>
    where R: Read, W: Write
{   
    let mut rng = OsRng::new().unwrap();
    let i_c = build_kexinit_payload(&neg, &mut rng).unwrap();
    let st = AlgorithmExchangeState {
        v_c: v_c,
        v_s: v_s,
        i_c: i_c,
        written: false,
        res: None
    };
    let kex = ClientKex::AlgorithmExchange(st);

    AsyncPacketTransport::new(reader, writer, rng, ClientKeyExchange { st: kex })
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
