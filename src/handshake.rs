use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use transport::{ntoh, unencrypted_read_packet, unencrypted_write_packet};

use std::{fmt, io, str};
use std::io::{Read, Write};
use futures::Future;
use rand::Rng;
use tokio_core::io::{flush, read_until, write_all};

use ::{SSH_MSG_KEYINIT, SSH_MSG_KEXDH_REPLY};

#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    InvalidVersionExchange,
    InvalidAlgorithmNegotiation,
    InvalidKexReply,
    InvalidServerCert,
    InvalidSignature,
    UnknownCertType(String)
}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> HandshakeError {
        HandshakeError::IoError(e)
    }
}

#[derive(Debug, Default)]
pub struct AlgorithmNegotiation {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool
}

pub struct AlgorithmNegotiationParser<'r> {
    buf: &'r [u8],
    pos: usize
}

impl <'r> AlgorithmNegotiationParser<'r> {
    fn new<'a>(buf: &'a [u8]) -> AlgorithmNegotiationParser<'a> {
        AlgorithmNegotiationParser {
            buf: buf,
            pos: 0
        }
    }

    fn parse_name_list(&mut self) -> Result<Vec<String>, HandshakeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(HandshakeError::InvalidAlgorithmNegotiation);
        }

        let list_len = ntoh(&self.buf[self.pos .. self.pos + 4]) as usize;
        self.pos += 4;

        if self.pos + list_len > self.buf.len() {
            return Err(HandshakeError::InvalidAlgorithmNegotiation);
        }

        let list: Result<Vec<String>, HandshakeError> = self.buf[self.pos .. self.pos + list_len]
            .split(|&c| c == b',')
            .map(|slice|
                 match str::from_utf8(slice) {
                     Ok(s) => Ok(s.to_owned()),
                     Err(_) => Err(HandshakeError::InvalidAlgorithmNegotiation)
                 }
            ).collect();
        self.pos += list_len;

        list
    }

    fn parse(&mut self) -> Result<AlgorithmNegotiation, HandshakeError> {
        let mut data: AlgorithmNegotiation = Default::default();

        if self.buf[0] != SSH_MSG_KEYINIT {
            return Err(HandshakeError::InvalidAlgorithmNegotiation);
        }

        self.pos = 17;

        data.kex_algorithms = try!(self.parse_name_list());
        data.server_host_key_algorithms = try!(self.parse_name_list());
        data.encryption_algorithms_client_to_server = try!(self.parse_name_list());
        data.encryption_algorithms_server_to_client = try!(self.parse_name_list());
        data.mac_algorithms_client_to_server = try!(self.parse_name_list());
        data.mac_algorithms_server_to_client = try!(self.parse_name_list());
        data.compression_algorithms_client_to_server = try!(self.parse_name_list());
        data.compression_algorithms_server_to_client = try!(self.parse_name_list());
        data.languages_client_to_server = try!(self.parse_name_list());
        data.languages_server_to_client = try!(self.parse_name_list());

        if self.pos != self.buf.len() - 5 {
            return Err(HandshakeError::InvalidAlgorithmNegotiation);
        }

        data.first_kex_packet_follows =
            match self.buf[self.pos] {
                0 => false,
                1 => true,
                _ => return Err(HandshakeError::InvalidAlgorithmNegotiation)
            };

        Ok(data)
    }
}

#[derive(Debug, Default)]
pub struct KexReply {
    pub server_cert: ServerCert,
    pub f: Vec<u8>,
    pub signature: Signature
}

pub struct KexReplyParser<'r> {
    buf: &'r [u8],
    pos: usize
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum ServerCert {
    SSH_RSA { e: Vec<u8>, n: Vec<u8> }
}

impl Default for ServerCert {
    fn default() -> ServerCert {
        ServerCert::SSH_RSA { e: Default::default(), n: Default::default() }
    }
}

impl <'r> KexReplyParser<'r> {
    fn new<'a>(buf: &'a [u8]) -> KexReplyParser<'a> {
        KexReplyParser {
            buf: buf,
            pos: 0
        }
    }

    fn parse_string(&mut self) -> Result<&[u8], HandshakeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(HandshakeError::InvalidKexReply);
        }

        let list_len = ntoh(&self.buf[self.pos .. self.pos + 4]) as usize;
        self.pos += 4;

        if self.pos + list_len > self.buf.len() {
            return Err(HandshakeError::InvalidKexReply);
        }

        let old_pos = self.pos;
        self.pos += list_len;

        Ok(&self.buf[old_pos .. self.pos])
    }

    fn parse(&mut self) -> Result<KexReply, HandshakeError> {
        let mut data: KexReply = Default::default();

        if self.buf[0] != SSH_MSG_KEXDH_REPLY {
            return Err(HandshakeError::InvalidKexReply);
        }

        self.pos = 1;

        data.server_cert = {
            let server_cert = try!(self.parse_string());
            try!(ServerCertParser::new(server_cert).parse())
        };
        data.f = try!(self.parse_string()).to_vec();
        data.signature = {
            let signature = try!(self.parse_string());
            try!(SignatureParser::new(signature).parse())
        };

        if self.pos != self.buf.len() {
            return Err(HandshakeError::InvalidKexReply);
        }

        Ok(data)
    }
}

pub struct ServerCertParser<'r> {
    buf: &'r [u8],
    pos: usize
}

impl <'r> ServerCertParser<'r> {
    fn new<'n>(buf: &'n [u8]) -> ServerCertParser<'n> {
        ServerCertParser {
            buf: buf,
            pos: 0
        }
    }

    fn parse_string(&mut self) -> Result<&[u8], HandshakeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(HandshakeError::InvalidServerCert);
        }

        let list_len = ntoh(&self.buf[self.pos .. self.pos + 4]) as usize;
        self.pos += 4;

        if self.pos + list_len > self.buf.len() {
            return Err(HandshakeError::InvalidServerCert);
        }

        let old_pos = self.pos;
        self.pos += list_len;

        Ok(&self.buf[old_pos .. self.pos])
    }

    fn parse(&mut self) -> Result<ServerCert, HandshakeError> {
        match try!(self.parse_string()) {
            b"ssh-rsa" => {
                let e = try!(self.parse_string()).to_vec();
                let n = try!(self.parse_string()).to_vec();
                Ok(ServerCert::SSH_RSA { e: e, n: n })
            },
            _ => {
                self.pos = 0;
                let name = String::from_utf8_lossy(self.parse_string().unwrap()).into_owned();
                Err(HandshakeError::UnknownCertType(name))
            }
        }
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Signature {
    SSH_RSA(Vec<u8>)
}

impl Default for Signature {
    fn default() -> Signature {
        Signature::SSH_RSA(Vec::new())
    }
}

pub struct SignatureParser<'r> {
    buf: &'r [u8],
    pos: usize
}

impl <'r> SignatureParser<'r> {
    fn new<'n>(buf: &'n [u8]) -> SignatureParser<'n> {
        SignatureParser {
            buf: buf,
            pos: 0
        }
    }

    fn parse_string(&mut self) -> Result<&[u8], HandshakeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(HandshakeError::InvalidSignature);
        }

        let list_len = ntoh(&self.buf[self.pos .. self.pos + 4]) as usize;
        self.pos += 4;

        if self.pos + list_len > self.buf.len() {
            return Err(HandshakeError::InvalidSignature);
        }

        let old_pos = self.pos;
        self.pos += list_len;

        Ok(&self.buf[old_pos .. self.pos])
    }

    fn parse(&mut self) -> Result<Signature, HandshakeError> {
        match try!(self.parse_string()) {
            b"ssh-rsa" => {
                let s = try!(self.parse_string()).to_vec();
                Ok(Signature::SSH_RSA(s))
            },
            _ => {
                self.pos = 0;
                let name = String::from_utf8_lossy(self.parse_string().unwrap()).into_owned();
                Err(HandshakeError::UnknownCertType(name))
            }
        }
    }
}

fn write_named_list<W: Write, S: AsRef<[u8]>>(writer: &mut W, list: &[S]) -> io::Result<()> {
    let len = if list.len() == 0 {
        0
    } else {
        list.iter().map(|s| s.as_ref().len()).sum::<usize>() + list.len() - 1
    };

    if len > 0xffffffff {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "named_list too long"));
    }

    let mut header = [0u8; 4];
    header[0] = (len >> 24) as u8;
    header[1] = (len >> 16) as u8;
    header[2] = (len >> 8) as u8;
    header[3] = len as u8;

    try!(writer.write(&header));
    let mut first = true;

    for name in list {
        if first {
            first = false;
        } else {
            try!(writer.write(b","));
        }

        try!(writer.write(name.as_ref()));
    }

    Ok(())
}

impl AlgorithmNegotiation {
    pub fn build_message(&self, rng: &mut Rng) -> Result<Vec<u8>, HandshakeError> {
        let mut payload = Vec::new();
        try!(payload.write(&[SSH_MSG_KEYINIT]));
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        try!(payload.write(&cookie));
        try!(write_named_list(&mut payload, &self.kex_algorithms));
        try!(write_named_list(&mut payload, &self.server_host_key_algorithms));
        try!(write_named_list(&mut payload, &self.encryption_algorithms_client_to_server));
        try!(write_named_list(&mut payload, &self.encryption_algorithms_server_to_client));
        try!(write_named_list(&mut payload, &self.mac_algorithms_client_to_server));
        try!(write_named_list(&mut payload, &self.mac_algorithms_server_to_client));
        try!(write_named_list(&mut payload, &self.compression_algorithms_client_to_server));
        try!(write_named_list(&mut payload, &self.compression_algorithms_server_to_client));
        try!(write_named_list(&mut payload, &self.languages_client_to_server));
        try!(write_named_list(&mut payload, &self.languages_server_to_client));
        let flag: u8 = if self.first_kex_packet_follows { 1 } else { 0 };
        try!(payload.write(&[flag]));
        try!(payload.write(&[0u8; 4]));

        Ok(payload)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HandshakeError::IoError(ref e) =>
                e.fmt(f),
            HandshakeError::InvalidVersionExchange =>
                write!(f, "InvalidVersionExchange"),
            HandshakeError::InvalidAlgorithmNegotiation =>
                write!(f, "InvalidAlgorithmNegotiation"),
            HandshakeError::InvalidKexReply =>
                write!(f, "InvalidKexReply"),
            HandshakeError::InvalidServerCert =>
                write!(f, "InvalidServerCert"),
            HandshakeError::InvalidSignature =>
                write!(f, "InvalidSignature"),
            HandshakeError::UnknownCertType(ref s) =>
                write!(f, "UnknownCertType({})", s)
        }
    }
}

pub fn version_exchange<R, W>(reader: AsyncBufReader<R>, writer: AsyncBufWriter<W>, version_string: &str, comment: &str)
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, Vec<u8>), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static
{
    let mut buf = Vec::with_capacity(256);
    write!(buf, "SSH-2.0-{} {}\r\n", version_string, comment).unwrap();
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    let w = write_all(writer, buf).and_then(|(writer, _)| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = read_until(reader, b'\n', Vec::with_capacity(256)).map_err(|e| e.into()).and_then(|(reader, buf)| {
        if buf.starts_with(b"SSH-2.0-") && buf.ends_with(b"\r\n") {
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
    let payload = supported_algorithms.build_message(rng).unwrap();

    let w = unencrypted_write_packet(writer, payload, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());

    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, buf)| {
        let slice = buf.as_ref();
        let mut parser = AlgorithmNegotiationParser::new(slice);
        parser.parse().map(|neg| (reader, neg))
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
        -> Box<Future<Item=(AsyncBufReader<R>, AsyncBufWriter<W>, KexReply), Error=HandshakeError>>
    where R: Read + Send + 'static, W: Write + Send + 'static, RNG: Rng
{
    let kex_message: Vec<u8> = vec![30, 0, 0, 0, 65, 4, 127, 202, 122, 190, 158, 103, 140, 201, 18,
        153, 153, 33, 222, 230, 168, 75, 68, 68, 222, 48, 233, 43, 40, 242, 202, 142, 228, 170,
        46, 206, 82, 75, 42, 33, 123, 27, 56, 215, 137, 120, 141, 143, 52, 143, 232, 198, 33,
        61, 72, 15, 150, 124, 45, 57, 132, 180, 23, 75, 252, 29, 188, 149, 165, 71];

    let w = unencrypted_write_packet(writer, kex_message, rng).and_then(|writer| {
        flush(writer)
    }).map_err(|e| e.into());
    
    let r = unencrypted_read_packet(reader).map_err(|e| e.into()).and_then(|(reader, payload)| {
        let slice = payload.as_ref();
        let mut parser = KexReplyParser::new(slice);
        parser.parse().map(|reply| (reader, reply))
    });

    w.join(r).map(|(writer, (reader, packet))| (reader, writer, packet)).boxed()
}
