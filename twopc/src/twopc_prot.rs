use circuit::Circuit;
use crypto_core::{AbstractChannel, Block};
use rand::{CryptoRng, Rng};

use crate::{
    encode, receive_decode_info, receive_gc_table, receive_wirelabels, send_decode_info,
    send_gc_table, send_wirelabels, COReceiver, COSender, CotReceiver, CotSender, GCEvaluator,
    GCGenerator, GarbledCircuitTable, HalfGateEvaluator, HalfGateGenerator, KOSReceiver, KOSSender,
    OutputDecodeInfo, WireLabel,
};

use circuit::CircuitInput;
use std::io::Result;

pub enum Party {
    ALICE,
    BOB,
}

#[derive(Clone)]
pub enum GCParty {
    GEN(HalfGateGenerator),
    EVA(HalfGateEvaluator),
}

pub struct TwopcProtocol<C: AbstractChannel> {
    pub channel: C,
    pub party: Party,
    pub delta: Block,
    pub gc_party: GCParty,
}

impl<C: AbstractChannel> TwopcProtocol<C> {
    pub fn new<R: Rng + CryptoRng>(channel: C, party: Party, rng: &mut R) -> Self {
        match party {
            Party::ALICE => {
                let mut delta = rng.gen::<Block>();
                delta = delta.set_lsb();
                let gen = HalfGateGenerator::new(delta);
                let gc_party = GCParty::GEN(gen);
                Self {
                    channel,
                    party,
                    delta,
                    gc_party,
                }
            }
            Party::BOB => {
                let delta = Block::default();
                let eva = HalfGateEvaluator::new();
                let gc_party = GCParty::EVA(eva);
                Self {
                    channel,
                    party,
                    delta,
                    gc_party,
                }
            }
        }
    }

    pub fn compute<R: Rng + CryptoRng>(
        &mut self,
        party: Party,
        rng: &mut R,
        circ: &Circuit,
        input_alice: &[bool],
        input_bob: &[bool],
    ) -> Result<Vec<WireLabel>> {
        let mut res = Vec::<WireLabel>::new();
        let alice_len = input_alice.len();
        let bob_len = input_bob.len();

        match party {
            Party::ALICE => {
                let mut kosot = KOSSender::new(COReceiver);
                kosot
                    .send_init_with_delta(&mut self.channel, rng, self.delta)
                    .unwrap();

                let bob_input_blks = kosot.send(&mut self.channel, rng, bob_len).unwrap();
                let bob_input_zero_blks = bob_input_blks
                    .into_iter()
                    .map(|(x, _)| x)
                    .collect::<Vec<Block>>();

                let alice_input_zero_blks = (0..alice_len)
                    .into_iter()
                    .map(|_| rng.gen::<Block>())
                    .collect::<Vec<Block>>();

                let input_zero_blks = [alice_input_zero_blks, bob_input_zero_blks].concat();

                let input_zero_labels = (0..circ.ninput_wires)
                    .zip(input_zero_blks)
                    .map(|(id, label)| WireLabel { id, label })
                    .collect::<Vec<WireLabel>>();

                let input: Vec<CircuitInput> = input_alice
                    .iter()
                    .enumerate()
                    .map(|(id, value)| CircuitInput {
                        id,
                        value: Block::from(*value as u128),
                    })
                    .collect();

                let alice_wirelabels = encode(
                    &input_zero_labels[0..input_alice.len()].to_vec(),
                    &input,
                    self.delta,
                );
                send_wirelabels(&mut self.channel, &alice_wirelabels).unwrap();
                self.channel.flush().unwrap();

                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::GEN(mut gen) => {
                        let gc = gen.garble(rng, circ, &input_zero_labels).unwrap();
                        send_gc_table(&mut self.channel, &gc.gc_table).unwrap();
                        self.channel.flush().unwrap();

                        res = gc.output_zero_labels;
                        return Ok(res);
                    }
                    _ => {
                        return Ok(res);
                    }
                }
            }
            Party::BOB => {
                let mut kosot = KOSReceiver::new(COSender);
                kosot.receive_init(&mut self.channel, rng).unwrap();

                let bob_input_blks = kosot.receive(&mut self.channel, &input_bob, rng).unwrap();

                let bob_wirelabels = (alice_len..alice_len + bob_len)
                    .zip(bob_input_blks)
                    .map(|(id, label)| WireLabel { id, label })
                    .collect::<Vec<WireLabel>>();

                let mut alice_wirelabels = vec![
                    WireLabel {
                        id: 0,
                        label: Block::default()
                    };
                    alice_len
                ];

                receive_wirelabels(&mut self.channel, &mut alice_wirelabels).unwrap();

                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::EVA(mut eva) => {
                        let input_wirelabels = [alice_wirelabels, bob_wirelabels].concat();
                        let mut gc_table = GarbledCircuitTable::new(
                            vec![[Block::default(); 2]; circ.nand],
                            Block::default(),
                        );

                        receive_gc_table(&mut self.channel, &mut gc_table).unwrap();

                        res = eva.eval(circ, &gc_table, &input_wirelabels).unwrap();

                        return Ok(res);
                    }

                    _ => {
                        return Ok(res);
                    }
                }
            }
        }
    }

    pub fn finalize(
        &mut self,
        party: Party,
        output_zero_labels: &Vec<WireLabel>,
    ) -> Result<Vec<bool>> {
        let mut res = Vec::<bool>::new();
        match party {
            Party::ALICE => {
                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::GEN(gen) => {
                        let decode_info = gen.finalize(&output_zero_labels);
                        send_decode_info(&mut self.channel, &decode_info).unwrap();
                        return Ok(res);
                    }

                    _ => {
                        return Ok(res);
                    }
                }
            }
            Party::BOB => {
                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::EVA(eva) => {
                        let mut decode_info = vec![
                            OutputDecodeInfo {
                                id: 0,
                                decode_info: false
                            };
                            output_zero_labels.len()
                        ];

                        receive_decode_info(&mut self.channel, &mut decode_info).unwrap();
                        res = eva.finalize(output_zero_labels, &decode_info);
                        return Ok(res);
                    }

                    _ => {
                        return Ok(res);
                    }
                }
            }
        }
    }

    // pub fn composite<R: Rng + CryptoRng>(
    //     party: Party,
    //     rng: &mut R,
    //     circ: &Circuit,
    //     input: &[bool],
    // ) {
    //     match party {
    //         Party::ALICE => {}
    //         Party::BOB => {}
    //     }
    // }

    pub fn reveal() {}
}

#[cfg(test)]
mod tests {

    use circuit::Circuit;
    use crypto_core::{local_channel_pair, AesRng};
    use std::thread;

    use crate::{Party, TwopcProtocol};

    #[test]
    fn twopc_basic_test() {
        // // m1 = 2^64 - 1
        // let m1 = vec![true; 64];
        // // m2 = 1
        // let mut m2 = vec![false; 64];
        // m2[0] = true;

        let expected_res = vec![false; 64];

        let (sender, receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            let m1 = vec![true; 64];
            let m2 = vec![false; 64];
            let mut rng = AesRng::new();
            let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

            let mut prot = TwopcProtocol::new(sender, Party::ALICE, &mut rng);
            let output_zero_labels = prot
                .compute(Party::ALICE, &mut rng, &circ, &m1, &m2)
                .unwrap();
            let _res = prot.finalize(Party::ALICE, &output_zero_labels).unwrap();
        });

        let m1 = vec![false; 64];
        let mut m2 = vec![false; 64];
        m2[0] = true;

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        let mut prot = TwopcProtocol::new(receiver, Party::BOB, &mut rng);
        let output_zero_labels = prot.compute(Party::BOB, &mut rng, &circ, &m1, &m2).unwrap();

        let res = prot.finalize(Party::BOB, &output_zero_labels).unwrap();
        assert_eq!(res, expected_res);
        handle.join().unwrap();
    }
}
