use std::net::TcpStream;
use structopt::StructOpt;

use crypto_core::{AbstractChannel, Block, NetChannel, CommandLineOpt};
use rand::random;

fn net_channel_test(netio: &mut NetChannel<TcpStream, TcpStream>) {
    if netio.is_server() {
        let send_bytes = random::<[u8; 10]>();
        let send_bool = random::<bool>();
        let send_bools = random::<[bool; 10]>();
        let send_block = random::<Block>();

        println!("send_bytes: {:?}", send_bytes);
        println!("send_bool: {:?}", send_bool);
        println!("send_bools: {:?}", send_bools);
        println!("send_block: {:?}", send_block);

        netio.write_bytes(&send_bytes).unwrap();
        netio.write_bool(send_bool).unwrap();
        netio.write_bools(&send_bools).unwrap();
        netio.write_block(&send_block).unwrap();

        netio.flush().unwrap();
    } else {
        let mut recv_bytes = [0u8; 10];
        netio.read_bytes(&mut recv_bytes).unwrap();
        let recv_bool = netio.read_bool().unwrap();
        let recv_bools = netio.read_bools(10).unwrap();
        let recv_block = netio.read_block().unwrap();

        println!("recv_bytes: {:?}", recv_bytes);
        println!("recv_bool: {:?}", recv_bool);
        println!("recv_bools: {:?}", recv_bools);
        println!("recv_block: {:?}", recv_block);
    }
}


// run the main function in two terminals
// cargo run --example netio -- --is-server 1
// cargo run --example netio -- --is-server 0
pub fn main() {
    let opt = CommandLineOpt::from_args();
    let is_server = opt.is_server != 0;
    let mut netio = NetChannel::new(is_server, "127.0.0.1:12345");
    net_channel_test(&mut netio);
}
