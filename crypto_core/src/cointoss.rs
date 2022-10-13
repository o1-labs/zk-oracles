//! Implement cointossing for two parties to generate public random values.

use rand::{CryptoRng, Rng};

use crate::{AbstractChannel, Block, Commitment};

pub struct CoinToss;

impl CoinToss {
    pub fn send<C: AbstractChannel, R: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut R,
        //num: usize,
    ) -> Block {
        let seed_s = rng.gen::<Block>();
        let r_s = rng.gen::<[u8; 16]>();

        // Commit seed_s and send the commitment to receiver.
        let comm_s = Commitment::commit(&seed_s.as_ref(), &r_s);
        channel.write_bytes(&comm_s).unwrap();
        channel.flush().unwrap();

        // Receive the commitment from receiver.
        let mut comm_r = [0u8; 32];
        channel.read_bytes(&mut comm_r).unwrap();

        // Recive the opening from receiver.
        let mut seed_and_rand_r = [0u8; 32];
        channel.read_bytes(&mut seed_and_rand_r).unwrap();

        // Check commitment.
        let seed_r = &seed_and_rand_r[0..16];
        let r = &seed_and_rand_r[16..32];
        if Commitment::check(seed_r, r, &comm_r) {
            let seed = seed_s ^ Block::try_from_slice(seed_r).unwrap();

            // Send openning to receiver.
            let seed_and_rand_s = [seed_s.as_ref(), r_s.as_ref()].concat();
            channel.write_bytes(&seed_and_rand_s).unwrap();
            channel.flush().unwrap();

            // Output seed
            seed
        } else {
            panic!("Commitment check failed")
        }
    }
    pub fn receive<C: AbstractChannel, R: Rng + CryptoRng>(
        channel: &mut C,
        rng: &mut R,
    ) -> Block {
        // Receive the commitment from sender.
        let mut comm_s = [0u8; 32];
        channel.read_bytes(&mut comm_s).unwrap();

        let seed_r = rng.gen::<Block>();
        let r_r = rng.gen::<[u8; 16]>();

        // Commit seed_r and send the commitment to sender.
        let comm_r = Commitment::commit(&seed_r.as_ref(), &r_r);
        channel.write_bytes(&comm_r).unwrap();
        channel.flush().unwrap();

        // Send opening to sender.
        let seed_and_rand_r = [seed_r.clone().as_ref(), r_r.as_ref()].concat();
        channel.write_bytes(&seed_and_rand_r).unwrap();
        channel.flush().unwrap();

        // Receive opening from sender.
        let mut seed_and_rand_s = [0u8; 32];
        channel.read_bytes(&mut seed_and_rand_s).unwrap();

        let seed_s = &seed_and_rand_s[0..16];
        let r = &seed_and_rand_s[16..32];

        if Commitment::check(seed_s, r, &comm_s) {
            let seed = seed_r ^ Block::try_from_slice(seed_s).unwrap();
            seed
        } else {
            panic!("Commitment check failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{local_channel_pair, AesRng, CoinToss, AbstractChannel};
    use std::thread;

    #[test]
    fn cointoss_test() {
        let (mut sender, mut receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            let mut rng = AesRng::new();
            let res = CoinToss::send(&mut sender, &mut rng);
            sender.write_block(&res).unwrap();
        });

        let mut rng = AesRng::new();
        let res = CoinToss::receive(&mut receiver, &mut rng);

        let res2 = receiver.read_block().unwrap();
        assert_eq!(res,res2);

        handle.join().unwrap();
    }
}
