use async_bufread::AsyncBufRead;

use std::io;
use std::io::Read;

use futures::{Async, Poll};
use futures::stream::Stream;
use tokio_core::io::Io;

struct NamedListParser<'r, R: Read+'r> {
    inner: &'r mut AsyncBufRead<R>,
    header: Option<u32>
}

fn ntoh(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) + ((buf[1] as u32) << 16) + ((buf[2] as u32) << 8) + (buf[3] as u32)
}

impl <'r, R: Read+'r> Stream for NamedListParser<'r, R>
{
    type Item = Vec<Vec<u8>>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Vec<Vec<u8>>>, io::Error> {
        match self.header {
            None => match try!(self.inner.nb_read_exact(4)) {
                None => Ok(Async::NotReady),
                Some(buf) => {
                    self.header = Some(ntoh(buf));
                    self.poll()
                }
            },
            Some(n) => match try!(self.inner.nb_read_exact(n as usize)) {
                None => Ok(Async::NotReady),
                Some(buf) => {
                    self.header = None;
                    let ret: Vec<Vec<u8>> = buf.split(|&c| c == b',').map(|s| s.to_vec()).collect();
                    Ok(Async::Ready(Some(ret)))
                }
            }
        }
    }
}
