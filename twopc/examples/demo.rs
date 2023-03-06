use std::net::TcpStream;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::curves::vesta::{Vesta, VestaParameters};
use poly_commitment::srs::SRS;

use circuit::Circuit;
use crypto_core::{AbstractChannel, AesRng, Block, CommandLineOpt, NetChannel};
use structopt::StructOpt;
use twopc::twopc_prot::*;

type ScalarField = <Vesta as AffineCurve>::ScalarField;

fn scalar_field_to_bytes(
    x: ScalarField,
) -> Vec<Block> {
    let mut bytes: Vec<u8> = vec![];
    x.serialize(&mut bytes).unwrap();
    let data: Vec<Block> = bytes
        .chunks(16)
        .map(|chunk| Block::try_from_slice(chunk).unwrap())
        .collect();
    data
}

fn bytes_to_scalar_field(
    data: &Vec<Block>
) -> ScalarField {
    let mut bytes = vec![];
    for block in data.iter() {
        bytes.extend(block.as_ref().into_iter().map(|x| x.clone()));
    }
    CanonicalDeserialize::deserialize(&bytes[..]).unwrap()
}

fn send_scalar_field<C: AbstractChannel>(
    channel: &mut C,
    x: ScalarField,
) {
    let data = scalar_field_to_bytes(x);
    for block in data.iter() {
        channel.write_block(&block).unwrap();
    }
}

fn receive_scalar_field<C: AbstractChannel>(
    channel: &mut C,
) -> ScalarField {
    let mut data = scalar_field_to_bytes(ScalarField::zero());
    for block in data.iter_mut() {
        *block = channel.read_block().unwrap();
    }
    bytes_to_scalar_field(&data)
}

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

fn bytes_to_affine(
    data: &Vec<Block>,
) -> Option<ark_ec::short_weierstrass_jacobian::GroupAffine<VestaParameters>> {
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
    match de {
        Ok((x, y)) => {
            /* NB: This will need to be new_unchecked once we upgrade arkworks. */
            let curve_point = Vesta::new(x, y, false);
            if curve_point.is_on_curve() && curve_point.is_in_correct_subgroup_assuming_on_curve() {
                Some(curve_point)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn send_curve_point<C: AbstractChannel>(
    channel: &mut C,
    curve_point: ark_ec::short_weierstrass_jacobian::GroupAffine<VestaParameters>,
) {
    let data = affine_to_bytes(curve_point);
    for block in data.iter() {
        channel.write_block(&block).unwrap();
    }
}

fn receive_curve_point<C: AbstractChannel>(
    channel: &mut C,
) -> ark_ec::short_weierstrass_jacobian::GroupAffine<VestaParameters> {
    let mut data = affine_to_bytes(Vesta::prime_subgroup_generator());
    for block in data.iter_mut() {
        *block = channel.read_block().unwrap();
    }
    bytes_to_affine(&data).expect("to get a valid curve point")
}

fn demo(netio: NetChannel<TcpStream, TcpStream>) {
    let circ = Circuit::load("circuit/circuit_files/bristol/aes_128.txt").unwrap();

    let n = 1 << 7;
    let mut srs = SRS::<Vesta>::create(n);
    let domain = {
        let n = D::<ScalarField>::compute_size_of_domain(n).unwrap();
        D::<ScalarField>::new(n).unwrap()
    };
    srs.add_lagrange_basis(domain);

    if netio.is_server() {
        let input = vec![true; 128];
        let key = vec![false; 128]; // the value here is not important, could be anything.

        let mut rng = AesRng::new();

        // A random scalar to blind the multiples of all commitments
        let scale_blinder = ScalarField::rand(&mut rng);

        let blinded_commitments = {
            let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
            let mut res = Vec::with_capacity(circ.noutput_wires);
            for i in 0..circ.noutput_wires {
                let lagrange_point = computed_lagrange_commitments[i / 8].clone();
                let scalar = scale_blinder * &((1 << (i % 8)) as u64).into();
                let commitment = srs.mask(lagrange_point.scale(scalar), &mut rng);
                res.push(commitment);
            }
            res
        };

        let mut total_blinder = ScalarField::zero();

        let data_to_mask = Some({
            let mut data_to_mask = Vec::with_capacity(2 * circ.noutput_wires);
            for commitment in blinded_commitments.iter() {
                // Assume no chunking for now
                let blinder = commitment.blinders.unshifted[0];
                total_blinder += blinder;
                let zero_curve_point = srs.h.mul(blinder).into_affine();
                let one_curve_point = commitment.commitment.unshifted[0];
                data_to_mask.push(affine_to_bytes(zero_curve_point));
                data_to_mask.push(affine_to_bytes(one_curve_point));
            }
            data_to_mask
        });
        let mut prot =
            TwopcProtocol::<NetChannel<TcpStream, TcpStream>>::new(netio, Party::Garbler, &mut rng);
        let (output_zero_labels, _masked_data) = prot
            .compute(&mut rng, &circ, &input, &key, &data_to_mask)
            .unwrap();

        // Receive the blinded commitment from the evaluator
        let mut blinded_commitment = receive_curve_point(prot.channel()).into_projective();
        // Remove the blindings from the individual commitments
        blinded_commitment -= srs.h.mul(total_blinder);
        // Remove the scaled blinding
        blinded_commitment = blinded_commitment
            .into_affine()
            .mul(scale_blinder.inverse().unwrap());
        // Send the now-unhidden commitment and the scaling blinder
        send_curve_point(prot.channel(), blinded_commitment.into_affine());
        prot.channel().flush().unwrap();
        send_scalar_field(prot.channel(), scale_blinder);
        prot.channel().flush().unwrap();

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

        // A random blinder to protect against garbler commitment preimage attacks.
        let mut random_blinder = ScalarField::rand(&mut rng);

        let blinded_commitment = {
            // Initialize the commitment with a random blinding
            let mut commitment = srs.h.mul(random_blinder).into_affine();
            // Integrate the now-unmasked commitments from the garbler.
            if let Some(unmasked_data) = unmasked_data.as_ref() {
                for data in unmasked_data.iter() {
                    let res = bytes_to_affine(data);
                    if let Some(res) = res {
                        commitment += &res;
                    }
                }
            }
            commitment
        };

        // Send the blinding commitment for unblinding.
        send_curve_point(prot.channel(), blinded_commitment);
        prot.channel().flush().unwrap();

        // Receive the unblinded curve point and the scaling blinder.
        let final_commitment = receive_curve_point(prot.channel());
        let blinder_scale = receive_scalar_field(prot.channel());
        random_blinder /= blinder_scale;

        let res = prot.finalize(&output_zero_labels).unwrap();

        let res_fields: Vec<ScalarField> =
            res.chunks(8).map(|chunk|
                chunk.iter().enumerate().fold(0, |acc, (idx, i)| {
                    acc + (1 << idx) * (*i as u8)
                }).into()).collect();

        let computed_commitment = {
            // Doing this manually now, for debugging purposes
            let mut acc = srs.h.mul(random_blinder).into_affine();
            let computed_lagrange_commitments = srs.lagrange_bases.get(&domain.size()).unwrap();
            for (i, res_field) in res_fields.into_iter().enumerate() {
                let lagrange_point = computed_lagrange_commitments[i].clone();
                acc += &lagrange_point.scale(res_field).unshifted[0];
            }
            acc
        };

        println!("Got final commitment: {}", final_commitment);
        println!("Computed commitment: {}", computed_commitment);
        assert_eq!(final_commitment, computed_commitment);

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
