extern crate rssh;

extern crate futures;
extern crate rand;
extern crate tokio_core;

use rssh::async::bufreader::AsyncBufReader;
use rssh::async::bufwriter::AsyncBufWriter;

use std::net::SocketAddr;

use futures::Future;
use futures::stream::Stream;
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
