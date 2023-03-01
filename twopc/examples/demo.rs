use std::net::TcpStream;

use circuit::Circuit;
use crypto_core::{AesRng, CommandLineOpt, NetChannel};
use structopt::StructOpt;
use twopc::twopc_prot::*;

fn demo(netio: NetChannel<TcpStream, TcpStream>) {
    let circ = Circuit::load("circuit/circuit_files/bristol/aes_128.txt").unwrap();

    if netio.is_server() {
        let input = vec![true; 128];
        let key = vec![false; 128]; // the value here is not important, could be anything.

        let mut rng = AesRng::new();
        let mut prot =
            TwopcProtocol::<NetChannel<TcpStream, TcpStream>>::new(netio, Party::Garbler, &mut rng);
        let output_zero_labels = prot.compute(&mut rng, &circ, &input, &key).unwrap();
        let res = prot.finalize(&output_zero_labels).unwrap();
        let res = res
            .into_iter()
            .map(|i| (i as u8).to_string())
            .collect::<String>();
        let msg = input
            .into_iter()
            .map(|i| (i as u8).to_string())
            .collect::<String>();

        println!("=============================");
        println!("Compute AES with 2PC Protocol\n");
        println!("The message for this party is: (you could change it by yourself)");
        println!("{}\n", msg);
        println!("The Ciphertext of AES(key,msg) is:");
        println!("{}", res);
    } else {
        let input = vec![false; 128]; // the value here is not important, could be anything.
        let key = vec![false; 128];

        let mut rng = AesRng::new();
        let mut prot = TwopcProtocol::new(netio, Party::Evaluator, &mut rng);
        let output_zero_labels = prot.compute(&mut rng, &circ, &input, &key).unwrap();
        let res = prot.finalize(&output_zero_labels).unwrap();
        let res = res
            .into_iter()
            .map(|i| (i as u8).to_string())
            .collect::<String>();

        let key = key
            .into_iter()
            .map(|i| (i as u8).to_string())
            .collect::<String>();
        println!("=============================");
        println!("Compute AES with 2PC Protocol\n");
        println!("The key for this party is: (you could change it by yourself)");
        println!("{}\n", key);
        println!("The Ciphertext of AES(key,msg) is:");
        println!("{}", res);
    }
}

// run the main function in two terminals
// cargo run --example demo -- --is-server 1
// cargo run --example demo -- --is-server 0
pub fn main() {
    let opt = CommandLineOpt::from_args();
    let is_server = opt.is_server != 0;
    let netio = NetChannel::new(is_server, "127.0.0.1:12345");
    demo(netio);
}
