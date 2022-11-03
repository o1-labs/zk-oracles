//! Implement the KOS15 OT Extension protocol.

use crate::{CotReceiver, CotSender};
use crate::{OTReceiverError, OTSenderError};
use crate::{OtReceiver, OtSender};
use crypto_core::utils::{pack_bits, random_blocks, transpose, unpack_bits, xor, xor_inplace};
use crypto_core::{AbstractChannel, Block, AES_HASH};
use crypto_core::{AesRng, CoinToss};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

// Statistic Security Parameter
const SSP: usize = 40;

#[derive(Clone)]
pub struct KOSSender<OT: OtReceiver<Msg = Block>> {
    pub ot: OT,
    pub delta: Block,
    prgs: Vec<AesRng>,
}

impl<OT: OtReceiver<Msg = Block>> KOSSender<OT> {
    pub fn new(ot: OT) -> Self {
        Self {
            ot,
            delta: Block::default(),
            prgs: Vec::new(),
        }
    }

    pub fn send_init<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<(), OTReceiverError> {
        let delta = rng.gen::<[u8; 16]>();
        let inputs = unpack_bits(&delta, 128);
        let k = self.ot.receive(channel, &inputs, rng)?;
        let prgs = k.iter().map(|x| AesRng::from_seed(*x)).collect();
        self.delta = Block::from(delta);
        self.prgs = prgs;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block>> CotSender for KOSSender<OT> {
    type Msg = Block;

    fn send<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
        m: usize,
    ) -> Result<Vec<(Block, Block)>, OTSenderError> {
        let rows = 128;
        let m_align = if m % 8 != 0 { m + 8 - m % 8 } else { m };
        let cols = m_align + 128 + SSP;

        let mut qs = vec![0u8; rows * cols / 8];
        let zero = vec![0u8; cols / 8];
        let mut u = vec![0u8; cols / 8];

        let delta: [u8; 16] = self.delta.into();
        let delta_bool = unpack_bits(&delta, rows);

        // for test only
        let mut x = vec![0u8; cols / 8];
        channel.read_bytes(&mut x).unwrap();

        // Generate t_{Delta_i}
        // Receive u = t0 + t1 + x
        // Compute q = Delta_i * u + t_{Delta_i}
        for (j, (b, rng)) in delta_bool.iter().zip(self.prgs.iter_mut()).enumerate() {
            let mut q = &mut qs[j * cols / 8..(j + 1) * cols / 8];
            rng.fill_bytes(&mut q);

            // if j == 1 {
            //     println!("delta_1:{:?}", *b);
            //     println!("t_delta_1:{:?}", q);
            // }

            channel.read_bytes(&mut u).unwrap();
            xor_inplace(&mut q, if *b { &u } else { &zero });
        }
        let q = &qs[0..cols / 8];
        // println!("q:{:?}", q);
        if delta_bool[0] {
            println!("q:{:?}", q);
        } else {
            println!("q:{:?}", xor(&q, &x));
        }
        println!("delta_0:{:?}", delta_bool[0]);
        
        // Transpose q
        transpose(&qs, rows, cols);

        let q = &qs[0..16];
        let q_bits = unpack_bits(q, 128);

        //println!("delta:{:?}", delta_bool);
        //println!("q_bits:{:?}", q_bits);

        // Check consistency
        let chi = CoinToss::send(channel, rng, cols);
        let mut check = (Block::default(), Block::default());

        for i in 0..cols {
            let q = &qs[i * 16..(i + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let tmp = q.clmul(chi[i]);
            check = (check.0 ^ tmp.0, check.1 ^ tmp.1);
        }

        let x_value = channel.read_block().unwrap();
        let t0 = channel.read_block().unwrap();
        let t1 = channel.read_block().unwrap();

        let tmp = x_value.clmul(self.delta);
        check = (check.0 ^ tmp.0, check.1 ^ tmp.1);

        assert_eq!(check, (t0, t1));

        if check != (t0, t1) {
            return Err(OTSenderError::ConsistencyCheckFailed);
        }

        // Send H(j,qj) + H(j,qj+Delta) + Delta
        // Output (H(j,qj), H(j,qj)+Delta)
        let mut v: Vec<(Block, Block)> = Vec::new();
        for i in 0..m {
            let q = &qs[i * 16..(i + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let tmp = (
                AES_HASH.tccr_hash(Block::from(i as u128), q),
                AES_HASH.tccr_hash(Block::from(i as u128), q ^ self.delta),
            );
            v.push(tmp);
            channel.write_block(&(tmp.0 ^ tmp.1 ^ self.delta)).unwrap();
        }
        channel.flush().unwrap();
        Ok(v)
    }
}

#[derive(Clone)]
pub struct KOSReceiver<OT: OtSender<Msg = Block>> {
    pub ot: OT,
    prgs0: Vec<AesRng>,
    prgs1: Vec<AesRng>,
}

impl<OT: OtSender<Msg = Block>> KOSReceiver<OT> {
    pub fn new(ot: OT) -> Self {
        Self {
            ot,
            prgs0: Vec::new(),
            prgs1: Vec::new(),
        }
    }

    pub fn receive_init<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        rng: &mut R,
    ) -> Result<(), OTSenderError> {
        let k0 = random_blocks(rng, 128);
        let k1 = random_blocks(rng, 128);
        let inputs: Vec<(Block, Block)> = k0.into_iter().zip(k1).collect();
        self.ot.send(channel, &inputs, rng)?;
        let prgs0 = inputs.iter().map(|(x, _)| AesRng::from_seed(*x)).collect();
        let prgs1 = inputs.iter().map(|(_, y)| AesRng::from_seed(*y)).collect();

        self.prgs0 = prgs0;
        self.prgs1 = prgs1;
        Ok(())
    }
}

impl<OT: OtSender<Msg = Block> + Clone> CotReceiver for KOSReceiver<OT> {
    type Msg = Block;

    fn receive<C: AbstractChannel, R: CryptoRng + rand::Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut R,
    ) -> Result<Vec<Block>, OTReceiverError> {
        let rows = 128;
        let m = inputs.len();
        let m_align = if m % 8 != 0 { m + 8 - m % 8 } else { m };
        let cols = m_align + 128 + SSP;
        let mut x = pack_bits(inputs);
        x.extend((0..(cols - m_align) / 8).map(|_| rng.gen::<u8>()));

        let mut ts = vec![0u8; rows * cols / 8];
        let mut u = vec![0u8; cols / 8];

        // for test only
        channel.write_bytes(&x).unwrap();
        channel.flush().unwrap();

        // compute u = t0+t1+x
        for i in 0..rows {
            let mut t = &mut ts[i * cols / 8..(i + 1) * cols / 8];
            self.prgs0[i].fill_bytes(&mut t);
            self.prgs1[i].fill_bytes(&mut u);

            // if i == 1 {
            //     println!("t0:{:?}", t);
            //     println!("t1:{:?}", u);
            // }

            xor_inplace(&mut u, &t);
            xor_inplace(&mut u, &x);

            channel.write_bytes(&u).unwrap();
        }
        channel.flush().unwrap();

        let t = &ts[0..cols / 8];
        println!("t0_0:{:?}", t);

        transpose(&ts, rows, cols);

        let t = &ts[0..16];
        let t_bits = unpack_bits(t, 128);

        //println!("inputs 0: {:?}", inputs[0]);
        //println!("t_bits:{:?}", t_bits);

        let chi = CoinToss::receive(channel, rng, cols);

        let mut x_block = Block::default();
        let mut t_blocks = (Block::default(), Block::default());

        let r_bool = unpack_bits(&x, cols);

        for (i, y) in r_bool.into_iter().enumerate() {
            let ti = &ts[i * 16..(i + 1) * 16];
            let ti: [u8; 16] = ti.try_into().unwrap();
            let ti = Block::from(ti);
            x_block ^= if y { chi[i] } else { Block::default() };
            let tmp = ti.clmul(chi[i]);
            t_blocks = (t_blocks.0 ^ tmp.0, t_blocks.1 ^ tmp.1);
        }
        channel.write_block(&x_block).unwrap();
        channel.write_block(&t_blocks.0).unwrap();
        channel.write_block(&t_blocks.1).unwrap();
        channel.flush().unwrap();

        let mut v: Vec<Block> = Vec::new();

        for (i, b) in inputs.iter().enumerate() {
            let t = &ts[i * 16..(i + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();

            let y = channel.read_block().unwrap();
            let y = if *b { y } else { Block::default() };

            let h = AES_HASH.tccr_hash(Block::from(i as u128), Block::from(t));
            v.push(y ^ h);
        }

        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use crate::{COReceiver, COSender, CotReceiver, CotSender, KOSReceiver, KOSSender};
    use crypto_core::{local_channel_pair, AbstractChannel, AesRng};
    use std::thread;

    fn rand_bool_vec(size: usize) -> Vec<bool> {
        (0..size).map(|_| rand::random::<bool>()).collect()
    }

    #[test]
    fn local_kos_ote_test() {
        let m = 256;
        let select = rand_bool_vec(256);

        let (mut sender, mut receiver) = local_channel_pair();
        let handle = thread::spawn(move || {
            let mut kosot = KOSSender::new(COReceiver);
            let mut rng = AesRng::new();
            kosot.send_init(&mut sender, &mut rng).unwrap();
            let res = kosot.send(&mut sender, &mut rng, m).unwrap();
            let _ = res.iter().map(|(x, y)| {
                sender.write_block(&x).unwrap();
                sender.write_block(y).unwrap();
            });
            sender.flush().unwrap();
        });

        let mut rng = AesRng::new();
        let mut kosot = KOSReceiver::new(COSender);
        kosot.receive_init(&mut receiver, &mut rng).unwrap();

        let res = kosot.receive(&mut receiver, &select, &mut rng).unwrap();

        for (b, x) in select.iter().zip(res) {
            let v0 = receiver.read_block().unwrap();
            let v1 = receiver.read_block().unwrap();

            if *b {
                assert_eq!(x, v1);
            } else {
                assert_eq!(x, v0);
            }
        }

        handle.join().unwrap();
    }
}