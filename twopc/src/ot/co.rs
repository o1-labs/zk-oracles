//! Implementation of Chou-Orlandi oblivious transfer protocol (cf. <https://eprint.iacr.org/2015/267>)

use crypto_core::{AbstractChannel, Block};
use curve25519_dalek::constants;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};

use super::errors::{OTReceiverError, OTSenderError};
use crate::hash_to_block;
use crate::OtReceiver;
use crate::OtSender;
use curve25519_dalek::scalar::Scalar;
#[derive(Copy, Clone)]
pub struct COSender;

impl OtSender for COSender {
    type Msg = Block;

    fn send<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        mut rng: &mut R,
    ) -> Result<(), OTSenderError> {
        let y = Scalar::random(&mut rng);
        let s = &y * &constants::RISTRETTO_BASEPOINT_TABLE;
        channel.write_point(&s)?;
        channel.flush()?;

        let mut hasher = Sha256::new();
        hasher.update(s.compress().to_bytes());

        let t = y * s;

        let keys: Vec<(Block, Block)> = (0..inputs.len())
            .map(|_| {
                let r = channel.read_point().unwrap();
                let yr = y * r;
                let k0 = hash_to_block(hasher.clone(), &r, &yr);
                let k1 = hash_to_block(hasher.clone(), &r, &(yr - t));
                (k0, k1)
            })
            .collect();

        for (input, k) in inputs.iter().zip(keys.into_iter()) {
            let c0 = input.0 ^ k.0;
            let c1 = input.1 ^ k.1;
            channel.write_block(&c0)?;
            channel.write_block(&c1)?;
        }
        channel.flush()?;

        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct COReceiver;

impl OtReceiver for COReceiver {
    type Msg = Block;

    fn receive<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut R,
    ) -> Result<Vec<Block>, OTReceiverError> {
        let iden = RistrettoPoint::identity();
        let s = channel.read_point()?;
        let s_table = RistrettoBasepointTable::create(&s);

        let mut hasher = Sha256::new();
        hasher.update(s.compress().to_bytes());

        let key: Vec<Block> = inputs
            .iter()
            .map(|input| {
                let x = Scalar::random(&mut rng);
                let cs = if *input { s } else { iden };
                let r = cs + &x * &RISTRETTO_BASEPOINT_TABLE;
                channel.write_point(&r).unwrap();
                hash_to_block(hasher.clone(), &r, &(&x * &s_table))
            })
            .collect();
        channel.flush()?;

        inputs
            .iter()
            .zip(key.into_iter())
            .map(|(input, k)| {
                let c0 = channel.read_block()?;
                let c1 = channel.read_block()?;
                let c = k ^ if *input { c1 } else { c0 };
                Ok(c)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use crypto_core::{local_channel_pair, AesRng, Block};

    use crate::{COReceiver, COSender, OtReceiver, OtSender};

    fn rand_block_vec(size: usize) -> Vec<Block> {
        (0..size).map(|_| rand::random::<Block>()).collect()
    }

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    #[test]
    fn local_co_ot_test() {
        let m0 = rand_block_vec(128);
        let m1 = rand_block_vec(128);
        let m_inside: Vec<(Block, Block)> = m0.into_iter().zip(m1.into_iter()).collect();
        let m = m_inside.clone();
        let select = rand_bool_vec(128);

        let (mut sender, mut receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            let mut ot = COSender;
            let mut rng = AesRng::new();
            ot.send(&mut sender, &m_inside, &mut rng).unwrap();
            ot.send(&mut sender, &m_inside, &mut rng).unwrap();
        });

        let mut rng = AesRng::new();
        let mut ot = COReceiver;

        let result = ot.receive(&mut receiver, &select, &mut rng).unwrap();
        for i in 0..128 {
            assert_eq!(result[i], if select[i] { m[i].1 } else { m[i].0 });
        }

        let result = ot.receive(&mut receiver, &select, &mut rng).unwrap();
        for i in 0..128 {
            assert_eq!(result[i], if select[i] { m[i].1 } else { m[i].0 });
        }
        handle.join().unwrap();
    }
}
