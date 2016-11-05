extern crate rssh;

extern crate futures;
extern crate tokio_core;

use std::io::BufReader;
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
        let pair = futures::lazy(|| futures::finished(socket.split()));
        let amt = pair.and_then(|(reader, writer)| {
            rssh::exchange_version(BufReader::new(reader), writer, "RSSHS_0.1.0", "Hello")
        });

        let msg = amt.map(move |(_, _, buf)| {
            println!("sent message to: {}", addr);
            println!("got hello message: {}", String::from_utf8_lossy(&buf));
        }).map_err(|e| {
            panic!("error: {}", e);
        });

        handle.spawn(msg);

        Ok(())
    });

    l.run(done).unwrap();
}
