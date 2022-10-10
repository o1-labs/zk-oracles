use std::net::TcpStream;

use crypto_core::CommandLineOpt;
use crypto_core::{AesRng, Block, NetChannel};
use structopt::StructOpt;
use twopc::ot::{ChouOrlandiReceiver, ChouOrlandiSender, OtReceiver, OtSender};

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

fn coot_test(netio: &mut NetChannel<TcpStream, TcpStream>) {
    if netio.is_server() {
        let m0 = rand_block_vec(8);
        let m1 = rand_block_vec(8);
        let m: Vec<(Block, Block)> = m0.into_iter().zip(m1.into_iter()).collect();
        let mut rng = AesRng::new();
        let mut ot = ChouOrlandiSender;
        ot.send(netio, &m, &mut rng).unwrap();
        println!("send blocks: {:?}", m);
    } else {
        let select = rand_bool_vec(8);
        let mut rng = AesRng::new();
        let mut ot = ChouOrlandiReceiver;
        let result = ot.receive(netio, &select, &mut rng).unwrap();
        println!("select bits: {:?}", select);
        println!("received blocks: {:?}", result);
    }
}

// run the main function in two terminals
// cargo run --example ot -- --is-server 1
// cargo run --example ot -- --is-server 0
pub fn main() {
    let opt = CommandLineOpt::from_args();
    let is_server = opt.is_server != 0;
    let mut netio = NetChannel::new(is_server, "127.0.0.1:12345");
    coot_test(&mut netio);
}
