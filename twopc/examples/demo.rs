use std::net::TcpStream;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::curves::vesta::{Vesta, VestaParameters};

use circuit::Circuit;
use crypto_core::{AesRng, Block, CommandLineOpt, NetChannel};
use structopt::StructOpt;
use twopc::twopc_prot::*;

fn affine_to_bytes(
    curve_point: ark_ec::short_weierstrass_jacobian::GroupAffine<VestaParameters>,
) -> Vec<Block> {
    let x = curve_point.x;
    let y = curve_point.y;
    let mut bytes: Vec<u8> = vec![];
    (x, y).serialize(&mut bytes).unwrap();
    let data: Vec<Block> = bytes
        .chunks(16)
        .map(|chunk| Block::try_from_slice(chunk).unwrap())
        .collect();
    data
}

fn demo(netio: NetChannel<TcpStream, TcpStream>) {
    let circ = Circuit::load("circuit/circuit_files/bristol/aes_128.txt").unwrap();

    if netio.is_server() {
        let input = vec![true; 128];
        let key = vec![false; 128]; // the value here is not important, could be anything.

        let data_to_mask = Some({
            let mut data_to_mask = Vec::with_capacity(2 * circ.noutput_wires);
            for i in 0..circ.noutput_wires {
                let generator = Vesta::prime_subgroup_generator();
                let scalar = <Vesta as AffineCurve>::ScalarField::from((i + 1) as u64);
                let curve_point = generator.mul(scalar).into_affine();
                println!("res: {}", curve_point);
                let data = affine_to_bytes(curve_point);
                data_to_mask.push(data.clone());
                data_to_mask.push(data);
            }
            data_to_mask
        });

        let mut rng = AesRng::new();
        let mut prot =
            TwopcProtocol::<NetChannel<TcpStream, TcpStream>>::new(netio, Party::Garbler, &mut rng);
        let (output_zero_labels, _masked_data) = prot
            .compute(&mut rng, &circ, &input, &key, &data_to_mask)
            .unwrap();
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

        // the value here is not important, could be anything.
        let data_to_mask = {
            let generator = Vesta::prime_subgroup_generator();
            let data = affine_to_bytes(generator);
            Some(vec![data; 2 * circ.noutput_wires])
        };

        let mut rng = AesRng::new();
        let mut prot = TwopcProtocol::new(netio, Party::Evaluator, &mut rng);
        let (output_zero_labels, masked_data) = prot
            .compute(&mut rng, &circ, &input, &key, &data_to_mask)
            .unwrap();
        let unmasked_data: Option<Vec<Vec<Block>>> = masked_data.map(|masked_data| {
            masked_data
                .into_iter()
                .enumerate()
                .map(|(i, blocks)| {
                    blocks
                        .into_iter()
                        .map(|block| block ^ output_zero_labels[i / 2].label)
                        .collect()
                })
                .collect()
        });
        if let Some(unmasked_data) = unmasked_data.as_ref() {
            for data in unmasked_data.iter() {
                let mut bytes = vec![];
                for block in data.iter() {
                    bytes.extend(block.as_ref().into_iter().map(|x| x.clone()));
                }
                let de: Result<
                    (
                        <Vesta as AffineCurve>::BaseField,
                        <Vesta as AffineCurve>::BaseField,
                    ),
                    _,
                > = CanonicalDeserialize::deserialize(&bytes[..]);
                let res = {
                    match de {
                        Ok((x, y)) => {
                            /* NB: This will need to be new_unchecked once we upgrade arkworks. */
                            let curve_point = Vesta::new(x, y, false);
                            if curve_point.is_on_curve()
                                && curve_point.is_in_correct_subgroup_assuming_on_curve()
                            {
                                Some(curve_point)
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    }
                };
                if let Some(res) = res {
                    println!("res: {}", res)
                }
            }
        }
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
