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
enum GCParty {
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
        rng: &mut R,
        circ: &Circuit,
        input_garbler: &[bool],
        input_evaluator: &[bool],
        data_to_mask: &Option<Vec<Vec<Block>>>,
    ) -> Result<(Vec<WireLabel>, Option<Vec<Vec<Block>>>)> {
        let res;
        let garbler_len = input_garbler.len();
        let evaluator_len = input_evaluator.len();

        let TwopcProtocol {
            channel,
            delta,
            gc_party,
            public_one_label,
        } = &mut (*self);

        match gc_party {
            GCParty::GEN(gen) => {
                let mut kosot = KOSSender::new(COReceiver);
                kosot.send_init_with_delta(channel, rng, *delta).unwrap();

                let evaluator_input_blks = kosot.send(channel, rng, evaluator_len).unwrap();
                let evaluator_input_zero_blks = evaluator_input_blks
                    .into_iter()
                    .map(|(x, _)| x)
                    .collect::<Vec<Block>>();

                let garbler_input_zero_blks = (0..garbler_len)
                    .into_iter()
                    .map(|_| rng.gen::<Block>())
                    .collect::<Vec<Block>>();

                let input_zero_blks = [garbler_input_zero_blks, evaluator_input_zero_blks].concat();

                let input_zero_labels = (0..circ.ninput_wires)
                    .zip(input_zero_blks)
                    .map(|(id, label)| WireLabel { id, label })
                    .collect::<Vec<WireLabel>>();

                let input: Vec<CircuitInput> = input_garbler
                    .iter()
                    .enumerate()
                    .map(|(id, value)| CircuitInput {
                        id,
                        value: Block::from(*value as u128),
                    })
                    .collect();

                let garbler_wirelabels = encode(
                    &input_zero_labels[0..input_garbler.len()].to_vec(),
                    &input,
                    *delta,
                );
                send_wirelabels(channel, &garbler_wirelabels).unwrap();
                channel.flush().unwrap();

                {
                    let (gc, masked_data) = gen
                        .garble(rng, circ, &input_zero_labels, data_to_mask)
                        .unwrap();
                    *public_one_label = gc.gc_table.public_one_label;
                    send_gc_table(channel, &gc.gc_table).unwrap();
                    channel.flush().unwrap();

                    res = gc.output_zero_labels;
                    return Ok((res, masked_data));
                }
            }
            GCParty::EVA(eva) => {
                let mut kosot = KOSReceiver::new(COSender);
                kosot.receive_init(channel, rng).unwrap();

                let evaluator_input_blks = kosot.receive(channel, &input_evaluator, rng).unwrap();

                let evaluator_wirelabels = (garbler_len..garbler_len + evaluator_len)
                    .zip(evaluator_input_blks)
                    .map(|(id, label)| WireLabel { id, label })
                    .collect::<Vec<WireLabel>>();

                let mut garbler_wirelabels = vec![
                    WireLabel {
                        id: 0,
                        label: Block::default()
                    };
                    garbler_len
                ];

                receive_wirelabels(channel, &mut garbler_wirelabels).unwrap();

                {
                    let input_wirelabels = [garbler_wirelabels, evaluator_wirelabels].concat();
                    let mut gc_table = GarbledCircuitTable::new(
                        vec![[Block::default(); 2]; circ.nand],
                        Block::default(),
                    );

                    receive_gc_table(channel, &mut gc_table).unwrap();
                    *public_one_label = gc_table.public_one_label;

                    res = eva.eval(circ, &gc_table, &input_wirelabels).unwrap();

                    return Ok((res, None));
                }
            }
        }
    }

    pub fn finalize(&mut self, output_zero_labels: &Vec<WireLabel>) -> Result<Vec<bool>> {
        let mut res = Vec::<bool>::new();

        let TwopcProtocol {
            channel,
            delta: _,
            gc_party,
            public_one_label: _,
        } = &mut (*self);

        match gc_party {
            GCParty::GEN(gen) => {
                let decode_info = gen.finalize(&output_zero_labels);
                send_decode_info(channel, &decode_info).unwrap();
                return Ok(res);
            }
            GCParty::EVA(eva) => {
                let mut decode_info = vec![
                    OutputDecodeInfo {
                        id: 0,
                        decode_info: false
                    };
                    output_zero_labels.len()
                ];

                receive_decode_info(channel, &mut decode_info).unwrap();
                res = eva.finalize(output_zero_labels, &decode_info);
                return Ok(res);
            }
        }
    }

    pub fn composite<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
        input_wires: &Vec<WireLabel>,
        input: &Vec<bool>,
        input_party: Party,
        indicator: &HashMap<usize, usize>,
    ) -> Result<Vec<WireLabel>> {
        let res;
        let input_len = input.len();
        let input_wires_len = input_wires.len();
        let mut composed_input_wires = Vec::<WireLabel>::new();

        let TwopcProtocol {
            channel,
            delta,
            gc_party,
            public_one_label,
        } = &mut (*self);

        match gc_party {
            GCParty::GEN(gen) => {
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
                            *delta,
                        );
                        send_wirelabels(channel, &input_wirelabels).unwrap();
                    }

                    Party::Evaluator => {
                        let mut kosot = KOSSender::new(COReceiver);
                        kosot.send_init_with_delta(channel, rng, *delta).unwrap();

                        let input_blks = kosot.send(channel, rng, input_len).unwrap();
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

                {
                    let (gc, _masked_data) = gen
                        .compose(circ, &composed_input_wires, *public_one_label, &None)
                        .unwrap();

                    send_gc_table(channel, &gc.gc_table).unwrap();
                    channel.flush().unwrap();

                    res = gc.output_zero_labels;
                    return Ok(res);
                }
            }
            GCParty::EVA(eva) => {
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
                        receive_wirelabels(channel, &mut input_wirelabels).unwrap();

                        for i in input_wirelabels {
                            composed_input_wires.push(i);
                        }
                    }
                    Party::Evaluator => {
                        let mut kosot = KOSReceiver::new(COSender);
                        kosot.receive_init(channel, rng).unwrap();

                        let input_blks = kosot.receive(channel, &input, rng).unwrap();
                        for i in input_wires_len..input_wires_len + input_len {
                            composed_input_wires.push(WireLabel {
                                id: i,
                                label: input_blks[i - input_wires_len],
                            });
                        }
                    }
                }
                {
                    let mut gc_table = GarbledCircuitTable::new(
                        vec![[Block::default(); 2]; circ.nand],
                        Block::default(),
                    );

                    receive_gc_table(channel, &mut gc_table).unwrap();
                    let ind = indicator.clone();
                    res = eva
                        .compose(circ, &gc_table, &composed_input_wires, &Some(ind))
                        .unwrap();

                    // res = eva.eval(circ, &gc_table, &composed_input_wires).unwrap();

                    return Ok(res);
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
            let (output_zero_labels, _masked_data) =
                prot.compute(&mut rng, &circ, &m1, &m2, &None).unwrap();
            let _res = prot.finalize(&output_zero_labels).unwrap();
        });

        let m1 = vec![false; 64];
        let mut m2 = vec![false; 64];
        m2[0] = true;

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        let mut prot = TwopcProtocol::new(receiver, Party::Evaluator, &mut rng);
        let (output_zero_labels, _masked_data) =
            prot.compute(&mut rng, &circ, &m1, &m2, &None).unwrap();

        let res = prot.finalize(&output_zero_labels).unwrap();
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
            let (output_zero_labels, _masked_data) =
                prot.compute(&mut rng, &circ, &input, &key, &None).unwrap();
            let _res = prot.finalize(&output_zero_labels).unwrap();
        });

        let input = vec![false; 128]; // the value here is not important, could be anything.
        let key = vec![false; 128];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128.txt").unwrap();

        let mut prot = TwopcProtocol::new(receiver, Party::Evaluator, &mut rng);
        let (output_zero_labels, _masked_data) =
            prot.compute(&mut rng, &circ, &input, &key, &None).unwrap();

        let res = prot.finalize(&output_zero_labels).unwrap();
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
            let (output_zero_labels, _masked_data) =
                prot.compute(&mut rng, &circ, &m1, &m2, &None).unwrap();

            let out_labels = prot
                .composite(
                    &mut rng,
                    &circ,
                    &output_zero_labels,
                    &m3,
                    Party::Evaluator,
                    &map,
                )
                .unwrap();
            let _res = prot.finalize(&out_labels).unwrap();
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
        let (output_zero_labels, _masked_data) =
            prot.compute(&mut rng, &circ, &m1, &m2, &None).unwrap();

        let out_labels = prot
            .composite(
                &mut rng,
                &circ,
                &output_zero_labels,
                &m3,
                Party::Evaluator,
                &map,
            )
            .unwrap();

        let res = prot.finalize(&out_labels).unwrap();
        assert_eq!(res, expected_res);
        handle.join().unwrap();
    }
}
