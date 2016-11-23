use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use key::KeyBuilder;
use packet::types::*;
use packet::{deserialize, deserialize_msg, serialize, serialize_msg};
use transport::{AsyncPacketState, PacketWriteRequest, hton, unencrypted_read_packet, unencrypted_write_packet};

use std::{fmt, io, str};
use std::convert::TryFrom;
use std::io::{Read, Write};
use futures::{Async, Future, Poll};
use rand::Rng;
use ring::{agreement, digest, rand, signature};
use ring::digest::Context;
use tokio_core::io::{flush, read_until, write_all};
use untrusted;

use ::{SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY};

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

#[derive(Clone)]
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

pub struct SecureContext {
    neg_algorithm: NegotiatedAlgorithm,
    session_id: Vec<u8>
}

enum ClientKeyExchange {
    AlgorithmExchange(AlgorithmExchangeState),
    KeyExchange(KeyExchangeState),
    Agreed(Agreed)
}

impl Future for ClientKeyExchange {
    type Item = SecureContext;
    type Error = HandshakeError;

    fn poll(&mut self) -> Poll<SecureContext, HandshakeError> {
        let next_st = match *self {
            ClientKeyExchange::AlgorithmExchange(ref mut st) => {
                if let Async::Ready(kex) = try!(st.poll()) {
                    ClientKeyExchange::KeyExchange(kex)
                } else {
                    return Ok(Async::NotReady);
                }
            },
            ClientKeyExchange::KeyExchange(ref mut st) => {
                if let Async::Ready(agreed) = try!(st.poll()) {
                    ClientKeyExchange::Agreed(agreed)
                } else {
                    return Ok(Async::NotReady);
                }
            },
            ClientKeyExchange::Agreed(ref mut st) => {
                return st.poll();
            }
        };

        *self = next_st;

        Ok(Async::NotReady)
    }
}

impl AsyncPacketState for ClientKeyExchange {
    fn wants_read(&self) -> bool {
        match *self {
            ClientKeyExchange::AlgorithmExchange(ref st) => st.wants_read(),
            ClientKeyExchange::KeyExchange(ref st) => st.wants_read(),
            ClientKeyExchange::Agreed(ref st) => false,
        }
    }

    fn on_read(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        match *self {
            ClientKeyExchange::AlgorithmExchange(ref mut st) => st.on_read(msg),
            ClientKeyExchange::KeyExchange(ref mut st) => st.on_read(msg),
            ClientKeyExchange::Agreed(ref mut st) => unreachable!()
        }
    }

    fn wants_write(&self) -> Option<PacketWriteRequest> {
        match *self {
            ClientKeyExchange::AlgorithmExchange(ref st) => st.wants_write(),
            ClientKeyExchange::KeyExchange(ref st) => st.wants_write(),
            ClientKeyExchange::Agreed(ref st) => st.wants_write(),
        }
    }

    fn on_flush(&mut self) -> Result<(), Self::Error> {
        match *self {
            ClientKeyExchange::AlgorithmExchange(ref mut st) => st.on_flush(),
            ClientKeyExchange::KeyExchange(ref mut st) => st.on_flush(),
            ClientKeyExchange::Agreed(ref mut st) => st.on_flush(),
        }
    }
}

struct AlgorithmExchangeState {
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
                        hash_ctx: ctx,
                        priv_key: priv_key,
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
            Ok(neg) => {
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
                digest_bytes(&mut ctx, self.v_c.as_bytes());
                digest_bytes(&mut ctx, self.v_s.as_bytes());
                digest_bytes(&mut ctx, &self.i_c);
                digest_bytes(&mut ctx, msg);

                self.res = Some((algorithms, ctx));

                Ok(())
            }
        }
    }

    fn wants_write(&self) -> Option<PacketWriteRequest> {
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

struct KeyExchangeState {
    neg: NegotiatedAlgorithm,
    hash_ctx: Context,
    priv_key: agreement::EphemeralPrivateKey,
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
            Ok(reply) => {
                let pub_key = {
                    let &ServerKey::SSH_RSA { ref e, ref n } = &reply.server_key;
                    (
                        untrusted::Input::from(from_mpint(n)),
                        untrusted::Input::from(from_mpint(e))
                    )
                };
                let k_s = serialize(&reply.server_key).unwrap();
                self.hash_ctx.update(&k_s);
                self.hash_ctx.update(&self.e);
                self.hash_ctx.update(&reply.f);
                let server_pub_key = untrusted::Input::from(&reply.f);
                let k = try!(agreement::agree_ephemeral(self.priv_key, &agreement::X25519, server_pub_key, HandshakeError::KexFailed, |shared_secret| {
                    Ok(into_mpint(shared_secret))
                }));
                self.hash_ctx.update(&k);
                let hash = self.hash_ctx.finish();
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
            }
        }
    }

    fn wants_write(&self) -> Option<PacketWriteRequest> {
        if self.written {
            None
        } else {
            let payload = serialize_msg(SSH_MSG_KEXINIT, &KexInit { e: self.e.clone() }).unwrap();

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

struct Agreed {
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
    fn wants_write(&self) -> Option<PacketWriteRequest> {
        Some(PacketWriteRequest { payload: vec![SSH_MSG_NEWKEYS], flush: true })
    }

    fn on_flush(&mut self) -> Result<(), Self::Error> {
        self.new_key_sent = true;
        Ok(())
    }
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
