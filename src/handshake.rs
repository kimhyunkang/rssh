use async::bufreader::AsyncBufReader;
use async::bufwriter::AsyncBufWriter;
use transport::{ntoh, unencrypted_read_packet, unencrypted_write_packet};

use std::{fmt, io, str};
use std::io::{Read, Write};
use futures::Future;
use rand::Rng;
use tokio_core::io::{flush, read_until, write_all};

use ::SSH_MSG_KEYINIT;

#[derive(Debug)]
pub enum HandshakeError {
    IoError(io::Error),
    InvalidVersionExchange,
    InvalidAlgorithmNegotiation
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
            HandshakeError::IoError(ref e) => e.fmt(f),
            HandshakeError::InvalidVersionExchange => write!(f, "InvalidVersionExchange"),
            HandshakeError::InvalidAlgorithmNegotiation => write!(f, "InvalidAlgorithmNegotiation")
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
