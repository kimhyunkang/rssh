extern crate rssh;

extern crate futures;
extern crate rand;
extern crate tokio_core;

use rssh::async::bufreader::AsyncBufReader;
use rssh::async::bufwriter::AsyncBufWriter;
use rssh::handshake::AlgorithmNegotiation;

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
        let pair = futures::lazy(|| futures::finished(socket.split()));
        let amt = pair.and_then(|(reader, writer)| {
            rssh::handshake::version_exchange(
                AsyncBufReader::new(reader),
                AsyncBufWriter::new(writer),
                "RSSHS_0.1.0",
                "Hello"
            )
        }).and_then(|(reader, writer, version)| {
            let supported_algorithms = AlgorithmNegotiation {
                kex_algorithms: Vec::new(),
                server_host_key_algorithms: Vec::new(),
                encryption_algorithms_client_to_server: Vec::new(),
                encryption_algorithms_server_to_client: Vec::new(),
                mac_algorithms_client_to_server: Vec::new(),
                mac_algorithms_server_to_client: Vec::new(),
                compression_algorithms_client_to_server: Vec::new(),
                compression_algorithms_server_to_client: Vec::new(),
                languages_client_to_server: Vec::new(),
                languages_server_to_client: Vec::new(),
                first_kex_packet_follows: false
            };

            let mut rng = thread_rng();
            rssh::handshake::algorithm_negotiation(
                reader,
                writer,
                &supported_algorithms,
                &mut rng
            ).map(|(reader, writer, neg)| (reader, writer, version, neg))
        });

        let msg = amt.map(move |(_, _, version, neg)| {
            println!("sent message to: {}", addr);
            println!("got hello message: {}", String::from_utf8_lossy(&version));
            println!("got algorithm neg: {:?}", neg);
        }).map_err(|e| {
            panic!("error: {}", e);
        });

        handle.spawn(msg);

        Ok(())
    });

    l.run(done).unwrap();
}
