extern crate rssh;

extern crate futures;
extern crate rand;
extern crate tokio_core;

// use rssh::buffered_io::BufferedIo;

use std::net::SocketAddr;

// use futures::Future;
// use futures::stream::Stream;
// use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;

fn main() {
    let addr = "0.0.0.0:2022".parse::<SocketAddr>().unwrap();

    let mut l = Core::new().unwrap();
    // let handle = l.handle();

    // let socket = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on: {}", addr);

    /*
    let done = socket.incoming().for_each(move |(socket, addr)| {
        let pair = futures::lazy(|| futures::finished(socket));
        let amt = pair.and_then(|socket| {
            rssh::handshake::version_exchange(BufferedIo::new(socket), "RSSHS_0.1.0", "Hello")
        });

        let msg = amt.map(move |(_, version)| {
            println!("sent message to: {}", addr);
            println!("got hello message: {}", String::from_utf8_lossy(&version));
        }).map_err(|e| {
            panic!("error: {}", e);
        });

        handle.spawn(msg);

        Ok(())
    });

    l.run(done).unwrap();
    */
}
