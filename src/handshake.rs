use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use packet::types::{AlgorithmNegotiation, KexInit, KexReply};
use packet::{deserialize, deserialize_msg, serialize, serialize_msg};
use transport::{unencrypted_read_packet, unencrypted_write_packet};

use std::{fmt, io, str};
use std::io::{Read, Write};
use futures::Future;
use rand::Rng;
use ring;
use ring::{agreement, rand};
use tokio_core::io::{flush, read_until, write_all};
use untrusted;

use ::{SSH_MSG_KEXINIT, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY};

#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    InvalidVersionExchange,
    InvalidAlgorithmNegotiation(String),
    InvalidKexReply(String),
    UnknownCertType(String)
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
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, Vec<u8>), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    let mut buf = Vec::with_capacity(256);
    write!(buf, "SSH-2.0-{} {}\r\n", version_string, comment).unwrap();
    println!("V_C: SSH-2.0-{} {}", version_string, comment);
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    let w = write_all(writer, buf).and_then(|(writer, _)| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = read_until(reader, b'\n', Vec::with_capacity(256)).map_err(|e| e.into()).and_then(|(reader, buf)| {
        if buf.starts_with(b"SSH-2.0-") && buf.ends_with(b"\r\n") {
            println!("V_S: {:?}", &buf[.. buf.len() - 2]);
            Ok((reader, buf[8 .. buf.len()-2].to_vec()))
        } else {
            Err(HandshakeError::InvalidVersionExchange)
        }
    });

    w.join(r).map(|(writer, (reader, version))| (reader, writer, version)).boxed()
}

pub fn algorithm_negotiation<R, W, RNG>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, supported_algorithms: &AlgorithmNegotiation, rng: &mut RNG)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, AlgorithmNegotiation), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static, RNG: Rng
{
    let payload = build_kexinit_payload(supported_algorithms, rng).unwrap();
    println!("I_C: {:?}", &payload[1..]);

    let w = unencrypted_write_packet(writer, payload, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());

    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, buf)| {
        if buf[0] == SSH_MSG_KEXINIT {
            println!("I_S: {:?}", &buf[1..]);
            match deserialize::<AlgorithmNegotiation>(&buf[17..]) {
                Ok(neg) => Ok((reader, neg)),
                Err(e) => Err(HandshakeError::InvalidAlgorithmNegotiation(e.to_string()))
            }
        } else {
            Err(HandshakeError::InvalidAlgorithmNegotiation("SSH_MSG_KEXINIT not received".to_string()))
        }
    });

    w.join(r).map(|(writer, (reader, packet))| (reader, writer, packet)).boxed()
}

pub fn ecdh_sha2_nistp256_server<R, W>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, Vec<u8>), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    unencrypted_read_packet(reader).map_err(|e| e.into()).map(|(reader, buf)| {
        (reader, writer, buf)
    }).boxed()
}

pub fn ecdh_sha2_nistp256_client<R, W, RNG>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, rng: &mut RNG)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, KexReply, Vec<u8>), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static, RNG: Rng
{
    let ring_rng = rand::SystemRandom::new();
    let client_priv_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &ring_rng).unwrap();
    let mut key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
    client_priv_key.compute_public_key(&mut key[..client_priv_key.public_key_len()]).unwrap();
    let client_pub_key = &key[..client_priv_key.public_key_len()];
    println!("client_pub_key: {:?}", client_pub_key);

    let kex_init = KexInit { e: client_pub_key.to_vec() };
    let kex_message = serialize_msg(SSH_MSG_KEXDH_INIT, &kex_init).unwrap();

    let w = unencrypted_write_packet(writer, kex_message, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, payload)| {
        match deserialize_msg::<KexReply>(&payload) {
            Ok((msg_key, reply)) => if msg_key == SSH_MSG_KEXDH_REPLY {
                println!("K_S: {:?}", serialize(&reply.server_cert));
                println!("server_pub_key: {:?}", reply.f);
                let shared_secret = {
                    let server_pub_key = untrusted::Input::from(&reply.f);
                    agreement::agree_ephemeral(client_priv_key, &agreement::ECDH_P256, server_pub_key, ring::error::Unspecified, |shared_secret| {
                        println!("shared_secret: {:?}", shared_secret);
                        Ok(shared_secret.to_vec())
                    }).unwrap()
                };
                Ok((reader, reply, shared_secret))
            } else {
                Err(HandshakeError::InvalidKexReply("SSH_MSG_KEXDH_REPLY not received".to_string()))
            },
            Err(e) => Err(HandshakeError::InvalidKexReply(e.to_string()))
        }
    });

    w.join(r).map(|(writer, (reader, packet, shared_secret))| (reader, writer, packet, shared_secret)).boxed()
}
