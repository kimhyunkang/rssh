extern crate rssh;

extern crate futures;
extern crate rand;
extern crate tokio_core;

use rssh::async::bufreader::AsyncBufReader;
use rssh::async::bufwriter::AsyncBufWriter;
use rssh::handshake::AlgorithmNegotiation;

use std::net::SocketAddr;

use futures::Future;
use rand::thread_rng;
use tokio_core::io::Io;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;

fn main() {
    let addr = "127.0.0.1:22".parse::<SocketAddr>().unwrap();

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
    }).and_then(|(reader, writer, version)| {
        println!("got hello message: {}", String::from_utf8_lossy(&version));

        let supported_algorithms = AlgorithmNegotiation {
            kex_algorithms: vec!["ecdh-sha2-nistp256".to_string()],
            server_host_key_algorithms: vec!["ssh-rsa".to_string()],
            encryption_algorithms_client_to_server: vec!["aes256-cbc".to_string()],
            encryption_algorithms_server_to_client: vec!["aes256-cbc".to_string()],
            mac_algorithms_client_to_server: vec!["hmac-sha1".to_string()],
            mac_algorithms_server_to_client: vec!["hmac-sha1".to_string()],
            compression_algorithms_client_to_server: vec!["none".to_string()],
            compression_algorithms_server_to_client: vec!["none".to_string()],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false
        };

        let mut rng = thread_rng();
        rssh::handshake::algorithm_negotiation(
            reader,
            writer,
            &supported_algorithms,
            &mut rng
        )
    }).and_then(|(reader, writer, neg)| {
        let mut rng = thread_rng();
        println!("got algorithm neg: {:?}", neg);
        rssh::handshake::ecdh_sha2_nistp256_client(reader, writer, &mut rng)
    }).map(|(_, _, buf)| {
        println!("got key exchange: {:?}", buf);
    }).map_err(|e| {
        panic!("error: {}", e);
    });

    l.run(done).unwrap();
}
