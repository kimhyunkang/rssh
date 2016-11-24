extern crate rssh;

extern crate futures;
extern crate rand;
extern crate ring;
extern crate tokio_core;
extern crate untrusted;

use rssh::async::bufreader::AsyncBufReader;
use rssh::async::bufwriter::AsyncBufWriter;
use rssh::packet::types::{AlgorithmNegotiation, KexAlgorithm, ServerHostKeyAlgorithm, EncryptionAlgorithm, MacAlgorithm, CompressionAlgorithm};

use std::net::SocketAddr;

use futures::Future;
use tokio_core::io::Io;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

fn main() {
    let addr = "127.0.0.1:3022".parse::<SocketAddr>().unwrap();

    let mut l = Core::new().unwrap();
    let handle = l.handle();

    let socket = TcpStream::connect(&addr, &handle);

    println!("Connecting to: {}", addr);

    let done = socket.and_then(|stream| {
        println!("Connection successful");
        futures::finished(stream.split())
    }).map_err(|e| e.into()).and_then(|(reader, writer)| {
        rssh::handshake::version_exchange(
            AsyncBufReader::new(reader),
            AsyncBufWriter::new(writer),
            "RSSHS_0.1.0",
            "Hello"
        )
    }).and_then(|(reader, writer, (v_c, v_s))| {
        let supported_algorithms = AlgorithmNegotiation {
            kex_algorithms: vec![KexAlgorithm::CURVE25519_SHA256],
            server_host_key_algorithms: vec![ServerHostKeyAlgorithm::SSH_RSA],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::AES256_CTR],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::AES256_CTR],
            mac_algorithms_client_to_server: vec![MacAlgorithm::HMAC_SHA2_256],
            mac_algorithms_server_to_client: vec![MacAlgorithm::HMAC_SHA2_256],
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::NONE],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::NONE],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
            reserved: 0
        };

        rssh::handshake::client_key_exchange(reader, writer, supported_algorithms, v_c, v_s)
    }).map(|ctx| {
        println!("server key verified!");
        println!("ctx: {:?}", ctx);
    }).map_err(|e| {
        panic!("error: {}", e);
    });

    l.run(done).unwrap();
}
