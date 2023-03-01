//! Implement the 2PC protocol with garbled circuit and oblivious transfer.
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
use std::collections::HashMap;
use std::io::Result;

pub enum Party {
    Garbler,
    Evaluator,
}

#[derive(Clone)]
pub enum GCParty {
    GEN(HalfGateGenerator),
    EVA(HalfGateEvaluator),
}

pub struct TwopcProtocol<C: AbstractChannel> {
    channel: C,
    delta: Block,
    gc_party: GCParty,
    public_one_label: Block,
}

impl<C: AbstractChannel> TwopcProtocol<C> {
    pub fn new<R: Rng + CryptoRng>(channel: C, party: Party, rng: &mut R) -> Self {
        match party {
            Party::Garbler => {
                let mut delta = rng.gen::<Block>();
                delta = delta.set_lsb();
                let gen = HalfGateGenerator::new(delta);
                let gc_party = GCParty::GEN(gen);
                let public_one_label = Block::default();
                Self {
                    channel,
                    delta,
                    gc_party,
                    public_one_label,
                }
            }
            Party::Evaluator => {
                let delta = Block::default();
                let eva = HalfGateEvaluator::new();
                let gc_party = GCParty::EVA(eva);
                let public_one_label = Block::default();
                Self {
                    channel,
                    delta,
                    gc_party,
                    public_one_label,
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
            Party::Garbler => {
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
                        self.public_one_label = gc.gc_table.public_one_label;
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
            Party::Evaluator => {
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
                        self.public_one_label = gc_table.public_one_label;

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
            Party::Garbler => {
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
            Party::Evaluator => {
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

    pub fn composite<R: Rng + CryptoRng>(
        &mut self,
        party: Party,
        rng: &mut R,
        circ: &Circuit,
        input_wires: &Vec<WireLabel>,
        input: &Vec<bool>,
        input_party: Party,
        indicator: &HashMap<usize, usize>,
    ) -> Result<Vec<WireLabel>> {
        let mut res = Vec::<WireLabel>::new();
        let input_len = input.len();
        let input_wires_len = input_wires.len();
        let mut composed_input_wires = Vec::<WireLabel>::new();

        match party {
            Party::Garbler => {
                for wire in input_wires {
                    composed_input_wires.push(WireLabel {
                        id: *indicator.get(&wire.id).unwrap(),
                        label: wire.label,
                    });
                }
                match input_party {
                    Party::Garbler => {
                        for i in input_wires_len..input_wires_len + input_len {
                            composed_input_wires.push(WireLabel {
                                id: i,
                                label: rng.gen::<Block>(),
                            });
                        }

                        let c_input: Vec<CircuitInput> = (input_wires_len
                            ..input_wires_len + input_len)
                            .zip(input)
                            .map(|(id, value)| CircuitInput {
                                id,
                                value: Block::from(*value as u128),
                            })
                            .collect();

                        let input_wirelabels = encode(
                            &composed_input_wires[input_wires_len..input_wires_len + input_len]
                                .to_vec(),
                            &c_input,
                            self.delta,
                        );
                        send_wirelabels(&mut self.channel, &input_wirelabels).unwrap();
                    }

                    Party::Evaluator => {
                        let mut kosot = KOSSender::new(COReceiver);
                        kosot
                            .send_init_with_delta(&mut self.channel, rng, self.delta)
                            .unwrap();

                        let input_blks = kosot.send(&mut self.channel, rng, input_len).unwrap();
                        let input_zero_blks = input_blks
                            .into_iter()
                            .map(|(x, _)| x)
                            .collect::<Vec<Block>>();

                        for i in input_wires_len..input_wires_len + input_len {
                            composed_input_wires.push(WireLabel {
                                id: i,
                                label: input_zero_blks[i - input_wires_len],
                            });
                        }
                    }
                }

                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::GEN(mut gen) => {
                        let gc = gen
                            .compose(circ, &composed_input_wires, self.public_one_label)
                            .unwrap();

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
            Party::Evaluator => {
                for wire in input_wires {
                    composed_input_wires.push(WireLabel {
                        id: wire.id,
                        label: wire.label,
                    });
                }

                match input_party {
                    Party::Garbler => {
                        let mut input_wirelabels = vec![
                            WireLabel {
                                id: 0,
                                label: Block::default()
                            };
                            input_len
                        ];
                        receive_wirelabels(&mut self.channel, &mut input_wirelabels).unwrap();

                        for i in input_wirelabels {
                            composed_input_wires.push(i);
                        }
                    }
                    Party::Evaluator => {
                        let mut kosot = KOSReceiver::new(COSender);
                        kosot.receive_init(&mut self.channel, rng).unwrap();

                        let input_blks = kosot.receive(&mut self.channel, &input, rng).unwrap();
                        for i in input_wires_len..input_wires_len + input_len {
                            composed_input_wires.push(WireLabel {
                                id: i,
                                label: input_blks[i - input_wires_len],
                            });
                        }
                    }
                }
                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::EVA(mut eva) => {
                        let mut gc_table = GarbledCircuitTable::new(
                            vec![[Block::default(); 2]; circ.nand],
                            Block::default(),
                        );

                        receive_gc_table(&mut self.channel, &mut gc_table).unwrap();
                        let ind = indicator.clone();
                        res = eva
                            .compose(circ, &gc_table, &composed_input_wires, &Some(ind))
                            .unwrap();

                        // res = eva.eval(circ, &gc_table, &composed_input_wires).unwrap();

                        return Ok(res);
                    }

                    _ => {
                        return Ok(res);
                    }
                }
            }
        }
    }

    pub fn reveal() {}
}

#[cfg(test)]
mod tests {

    use circuit::Circuit;
    use crypto_core::{local_channel_pair, AesRng};
    use std::collections::HashMap;
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

            let mut prot = TwopcProtocol::new(sender, Party::Garbler, &mut rng);
            let output_zero_labels = prot
                .compute(Party::Garbler, &mut rng, &circ, &m1, &m2)
                .unwrap();
            let _res = prot.finalize(Party::Garbler, &output_zero_labels).unwrap();
        });

        let m1 = vec![false; 64];
        let mut m2 = vec![false; 64];
        m2[0] = true;

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        let mut prot = TwopcProtocol::new(receiver, Party::Evaluator, &mut rng);
        let output_zero_labels = prot.compute(Party::Evaluator, &mut rng, &circ, &m1, &m2).unwrap();

        let res = prot.finalize(Party::Evaluator, &output_zero_labels).unwrap();
        assert_eq!(res, expected_res);
        handle.join().unwrap();
    }

    #[test]
    fn twopc_aes_basic_test() {
        // let input = vec![true; 128];
        // let key = vec![false; 128];

        let (sender, receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            let input = vec![true; 128];
            let key = vec![false; 128]; // the value here is not important, could be anything.
            let mut rng = AesRng::new();
            let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128.txt").unwrap();

            let mut prot = TwopcProtocol::new(sender, Party::Garbler, &mut rng);
            let output_zero_labels = prot
                .compute(Party::Garbler, &mut rng, &circ, &input, &key)
                .unwrap();
            let _res = prot.finalize(Party::Garbler, &output_zero_labels).unwrap();
        });

        let input = vec![false; 128]; // the value here is not important, could be anything.
        let key = vec![false; 128];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128.txt").unwrap();

        let mut prot = TwopcProtocol::new(receiver, Party::Evaluator, &mut rng);
        let output_zero_labels = prot
            .compute(Party::Evaluator, &mut rng, &circ, &input, &key)
            .unwrap();

        let res = prot.finalize(Party::Evaluator, &output_zero_labels).unwrap();
        let res = res
            .into_iter()
            .map(|i| (i as u8).to_string())
            .collect::<String>();
        let expected_res = "00111111010110111000110011001001111010101000010101011010000010101111101001110011010001111101001000111110100011010110011001001110";
        assert_eq!(expected_res, res);
        handle.join().unwrap();
    }

    #[test]
    fn twopc_compose_test() {
        // Compose m1 + m2 + m3

        //  m1 = 2^64 -1
        // let m1 = vec![true; 64];
        //  m2 = 1
        // let mut m2 = vec![false; 64];
        // m2[0] = true;
        //  m3 = 1
        // let mut m3 = vec![false; 64];
        // m3[0] = true;
        //  res = 1
        // let mut res = vec![false; 64];
        // res[0] = true;

        let mut expected_res = vec![false; 64];
        expected_res[0] = true;

        let (sender, receiver) = local_channel_pair();

        let handle = thread::spawn(move || {
            let m1 = vec![true; 64];
            let m2 = vec![false; 64]; // no need to care about this value
            let m3 = vec![false; 64]; // no need to care about this value

            let mut rng = AesRng::new();
            let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

            // define the indicator map
            let mut map = HashMap::<usize, usize>::new();
            for i in circ.nwires - circ.noutput_wires..circ.nwires {
                map.insert(i, i - (circ.nwires - circ.noutput_wires));
            }

            for i in 64..128 {
                map.insert(i, i);
            }
            // let indicator = Some(map);

            let mut prot = TwopcProtocol::new(sender, Party::Garbler, &mut rng);
            let output_zero_labels = prot
                .compute(Party::Garbler, &mut rng, &circ, &m1, &m2)
                .unwrap();

            let out_labels = prot
                .composite(
                    Party::Garbler,
                    &mut rng,
                    &circ,
                    &output_zero_labels,
                    &m3,
                    Party::Evaluator,
                    &map,
                )
                .unwrap();
            let _res = prot.finalize(Party::Garbler, &out_labels).unwrap();
        });

        let m1 = vec![false; 64]; // no need to care about this value
        let mut m2 = vec![false; 64];
        m2[0] = true;
        let mut m3 = vec![false; 64];
        m3[0] = true; // the composition value is from Evaluator
        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        // define the indicator map
        let mut map = HashMap::<usize, usize>::new();
        for i in circ.nwires - circ.noutput_wires..circ.nwires {
            map.insert(i, i - (circ.nwires - circ.noutput_wires));
        }

        for i in 64..128 {
            map.insert(i, i);
        }
        // let indicator = Some(map);

        let mut prot = TwopcProtocol::new(receiver, Party::Evaluator, &mut rng);
        let output_zero_labels = prot.compute(Party::Evaluator, &mut rng, &circ, &m1, &m2).unwrap();

        let out_labels = prot
            .composite(
                Party::Evaluator,
                &mut rng,
                &circ,
                &output_zero_labels,
                &m3,
                Party::Evaluator,
                &map,
            )
            .unwrap();

        let res = prot.finalize(Party::Evaluator, &out_labels).unwrap();
        assert_eq!(res, expected_res);
        handle.join().unwrap();
    }
}
