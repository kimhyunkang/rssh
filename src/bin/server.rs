extern crate rssh;

extern crate futures;
extern crate rand;
extern crate tokio_core;

use rssh::async::bufreader::AsyncBufReader;
use rssh::async::bufwriter::AsyncBufWriter;
use rssh::packet::types::{AlgorithmNegotiation, KexAlgorithm, ServerHostKeyAlgorithm, EncryptionAlgorithm, MacAlgorithm, CompressionAlgorithm};

use std::net::SocketAddr;

use futures::Future;
use futures::stream::Stream;
use rand::thread_rng;
use tokio_core::io::Io;
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;

fn main() {
    let addr = "0.0.0.0:2022".parse::<SocketAddr>().unwrap();

    let mut l = Core::new().unwrap();
    let handle = l.handle();

    let socket = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on: {}", addr);

    let done = socket.incoming().for_each(move |(socket, addr)| {
        println!("New connection from: {}", addr);
        let pair = futures::lazy(|| futures::finished(socket.split()));
        let msg = pair.and_then(|(reader, writer)| {
            rssh::handshake::version_exchange(
                AsyncBufReader::new(reader),
                AsyncBufWriter::new(writer),
                "RSSHS_0.1.0",
                "Hello"
            )
        }).and_then(|(reader, writer, version)| {
            println!("got hello message: {}", String::from_utf8_lossy(&version));

            let supported_algorithms = AlgorithmNegotiation {
                kex_algorithms: vec![KexAlgorithm::ECDH_SHA2_NISTP256],
                server_host_key_algorithms: vec![ServerHostKeyAlgorithm::SSH_RSA],
                encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::AES256_CBC],
                encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::AES256_CBC],
                mac_algorithms_client_to_server: vec![MacAlgorithm::HMAC_SHA2_256],
                mac_algorithms_server_to_client: vec![MacAlgorithm::HMAC_SHA2_256],
                compression_algorithms_client_to_server: vec![CompressionAlgorithm::NONE],
                compression_algorithms_server_to_client: vec![CompressionAlgorithm::NONE],
                languages_client_to_server: vec![],
                languages_server_to_client: vec![],
                first_kex_packet_follows: false,
                reserved: 0
            };

            let mut rng = thread_rng();
            rssh::handshake::algorithm_negotiation(
                reader,
                writer,
                &supported_algorithms,
                &mut rng
            )
        }).and_then(|(reader, writer, neg)| {
            println!("got algorithm neg: {:?}", neg);

            rssh::handshake::ecdh_sha2_nistp256_server(reader, writer)
        }).map(|(_, _, buf)| {
            println!("got key exchange: {:?}", buf);
        }).map_err(|e| {
            panic!("error: {}", e);
        });

        handle.spawn(msg);

        Ok(())
    });

    l.run(done).unwrap();
}
