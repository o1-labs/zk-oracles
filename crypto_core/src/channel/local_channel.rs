use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

use crate::SynChannel;

pub type LocalChannel = SynChannel<BufReader<UnixStream>, BufWriter<UnixStream>>;

pub fn local_channel_pair() -> (LocalChannel, LocalChannel) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let sender = SynChannel::new(BufReader::new(tx.try_clone().unwrap()), BufWriter::new(tx));
    let receiver = SynChannel::new(BufReader::new(rx.try_clone().unwrap()), BufWriter::new(rx));
    (sender, receiver)
}
