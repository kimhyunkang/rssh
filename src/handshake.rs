use buffered_io::BufferedIo;
use transport::{NamedListParser, take_stream};

use std::{fmt, io};
use std::io::Write;
use futures::{Future, done};
use rand::Rng;
use tokio_core::io::{Io, flush, read_exact, read_until, write_all};

use ::SSH_MSG_KEYINIT;

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

#[derive(Debug)]
pub struct AlgorithmNegotiation {
    kex_algorithms: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_client_to_server: Vec<String>,
    encryption_algorithms_server_to_client: Vec<String>,
    mac_algorithms_client_to_server: Vec<String>,
    mac_algorithms_server_to_client: Vec<String>,
    compression_algorithms_client_to_server: Vec<String>,
    compression_algorithms_server_to_client: Vec<String>,
    languages_client_to_server: Vec<String>,
    languages_server_to_client: Vec<String>,
    first_kex_packet_follows: bool
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
        let mut buf = Vec::new();
        try!(buf.write(&[SSH_MSG_KEYINIT]));
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        try!(buf.write(&cookie));
        try!(write_named_list(&mut buf, &self.kex_algorithms));
        try!(write_named_list(&mut buf, &self.server_host_key_algorithms));
        try!(write_named_list(&mut buf, &self.encryption_algorithms_client_to_server));
        try!(write_named_list(&mut buf, &self.encryption_algorithms_server_to_client));
        try!(write_named_list(&mut buf, &self.mac_algorithms_client_to_server));
        try!(write_named_list(&mut buf, &self.mac_algorithms_server_to_client));
        try!(write_named_list(&mut buf, &self.compression_algorithms_client_to_server));
        try!(write_named_list(&mut buf, &self.compression_algorithms_server_to_client));
        try!(write_named_list(&mut buf, &self.languages_client_to_server));
        try!(write_named_list(&mut buf, &self.languages_server_to_client));
        let flag: u8 = if self.first_kex_packet_follows { 1 } else { 0 };
        try!(buf.write(&[flag]));
        try!(buf.write(&[0u8; 4]));

        Ok(buf)
    }

    pub fn from_name_lists(mut name_lists: Vec<Vec<String>>, first_kex_packet_follows: u8)
        -> Result<AlgorithmNegotiation, HandshakeError>
    {
        if name_lists.len() != 10 {
            return Err(HandshakeError::InvalidAlgorithmNegotiation);
        }

        let flag = match first_kex_packet_follows {
            0 => false,
            1 => true,
            _ => return Err(HandshakeError::InvalidAlgorithmNegotiation)
        };

        let l9 = name_lists.pop().unwrap();
        let l8 = name_lists.pop().unwrap();
        let l7 = name_lists.pop().unwrap();
        let l6 = name_lists.pop().unwrap();
        let l5 = name_lists.pop().unwrap();
        let l4 = name_lists.pop().unwrap();
        let l3 = name_lists.pop().unwrap();
        let l2 = name_lists.pop().unwrap();
        let l1 = name_lists.pop().unwrap();
        let l0 = name_lists.pop().unwrap();

        Ok(AlgorithmNegotiation {
            kex_algorithms: l0,
            server_host_key_algorithms: l1,
            encryption_algorithms_client_to_server: l2,
            encryption_algorithms_server_to_client: l3,
            mac_algorithms_client_to_server: l4,
            mac_algorithms_server_to_client: l5,
            compression_algorithms_client_to_server: l6,
            compression_algorithms_server_to_client: l7,
            languages_client_to_server: l8,
            languages_server_to_client: l9,
            first_kex_packet_follows: flag
        })
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

pub fn version_exchange<S>(stream: BufferedIo<S>, version_string: &str, comment: &str)
        -> Box<Future<Item=(BufferedIo<S>, Vec<u8>), Error=HandshakeError>>
    where S: Io + Send + 'static
{
    let mut buf = Vec::with_capacity(256);
    write!(buf, "SSH-2.0-{} {}\r\n", version_string, comment).unwrap();
    if buf.len() > 255 {
        panic!("version string and comment too long");
    }

    write_all(stream, buf).and_then(|(stream, _)| {
        flush(stream)
    }).and_then(|stream| {
        read_until(stream, b'\n', Vec::with_capacity(256))
    }).map_err(|e| {
        e.into()
    }).and_then(|(stream, buf)| {
        if buf.starts_with(b"SSH-2.0-") && buf.ends_with(b"\r\n") {
            Ok((stream, buf[8 .. buf.len()-2].to_vec()))
        } else {
            Err(HandshakeError::InvalidVersionExchange)
        }
    }).boxed()
}

pub fn algorithm_negotiation<S>(stream: BufferedIo<S>, supported_algorithms: &AlgorithmNegotiation, rng: &mut Rng)
        -> Box<Future<Item=(BufferedIo<S>, AlgorithmNegotiation), Error=HandshakeError>>
    where S: Clone + Io + Send + 'static
{
    done(supported_algorithms.build_message(rng)).and_then(|message| {
        write_all(stream, message).and_then(|(stream, _)| {
            flush(stream)
        }).and_then(|stream| {
            read_exact(stream, vec![0; 17])
        }).map_err(|e| e.into())
    }).and_then(|(stream, buf)| {
        if buf[0] == SSH_MSG_KEYINIT {
            Ok(stream)
        } else {
            Err(HandshakeError::InvalidAlgorithmNegotiation)
        }
    }).and_then(|stream| {
        take_stream(NamedListParser::new(stream), 10).and_then(|(parser, lists)| {
            read_exact(parser.into_inner(), vec![0; 5]).map(|(stream, buf)| (stream, lists, buf))
        }).then(|res| match res {
            Ok((stream, lists, buf)) =>
                AlgorithmNegotiation::from_name_lists(lists, buf[0]).map(|neg| (stream, neg)),
            Err(e) =>
                Err(e.into())
        })
    }).boxed()
}
