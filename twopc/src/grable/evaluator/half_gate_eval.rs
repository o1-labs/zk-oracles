use crypto_core::{block::SELECT_MASK, Block, AES_HASH};

use crate::EvaluatorError;
use crate::GCEvaluator;
use crate::GarbledCircuit;
use crate::InputLabel;
use circuit::gate::Gate;

pub struct HalfGateEvaluator;

impl HalfGateEvaluator {
    #[inline]
    pub fn and_gate(&self, x: Block, y: Block, table: [Block; 2], gid: usize) -> Block {
        let sa = x.lsb() as usize;
        let sb = y.lsb() as usize;

        let index = gid as u128;
        let index_next = (gid + 1) as u128;

        let hash_x = AES_HASH.tccr_hash(index.into(), x);
        let hash_y = AES_HASH.tccr_hash(index_next.into(), y);

        let w_g = hash_x ^ (SELECT_MASK[sa] & table[0]);
        let w_e = hash_y ^ (SELECT_MASK[sb] & (table[1] ^ x));

        w_g ^ w_e
    }

    #[inline]
    pub fn xor_gate(&self, x: Block, y: Block) -> Block {
        x ^ y
    }

    #[inline]
    pub fn inv_gate(&self, x: Block, public_one_label: Block) -> Block {
        x ^ public_one_label
    }
}

impl GCEvaluator for HalfGateEvaluator {
    fn eval(
        &self,
        circ: &circuit::Circuit,
        gc: &GarbledCircuit,
        evaluator_input_labels: &[InputLabel],
    ) -> Result<Vec<bool>, EvaluatorError> {
        let input_labels = [
            gc.generator_input_labels.clone(),
            evaluator_input_labels.to_vec(),
        ]
        .concat();
        assert_eq!(
            input_labels.len(),
            circ.ninput_wires,
            "Number of input wires is not consistent!"
        );

        let mut wire_labels: Vec<Option<Block>> = vec![None; circ.nwires];

        for input_label in input_labels {
            wire_labels[input_label.id] = Some(input_label.label);
        }

        let mut gid = 1;
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { lin_id, out_id, .. } => {
                    let x =
                        wire_labels[lin_id].ok_or(EvaluatorError::UninitializedLabel(lin_id))?;
                    let z = self.inv_gate(x, gc.public_one_label);

                    wire_labels[out_id] = Some(z);
                }
                Gate::Xor {
                    lin_id,
                    rin_id,
                    out_id,
                    ..
                } => {
                    let x =
                        wire_labels[lin_id].ok_or(EvaluatorError::UninitializedLabel(lin_id))?;
                    let y =
                        wire_labels[rin_id].ok_or(EvaluatorError::UninitializedLabel(rin_id))?;
                    let z = self.xor_gate(x, y);

                    wire_labels[out_id] = Some(z);
                }
                Gate::And {
                    lin_id,
                    rin_id,
                    out_id,
                    ..
                } => {
                    let x =
                        wire_labels[lin_id].ok_or(EvaluatorError::UninitializedLabel(lin_id))?;
                    let y =
                        wire_labels[rin_id].ok_or(EvaluatorError::UninitializedLabel(rin_id))?;
                    let z = self.and_gate(x, y, gc.table[gid - 1], gid);

                    wire_labels[out_id] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut outputs: Vec<bool> = Vec::with_capacity(circ.noutput_wires);
        for (i, id) in ((circ.nwires - circ.noutput_wires)..circ.nwires).enumerate() {
            outputs.push((wire_labels[id].unwrap().lsb()) ^ gc.output_bits[i]);
        }
        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use circuit::{Circuit, CircuitInput};
    use crypto_core::{AesRng, Block};

    use crate::{GCEvaluator, GCGenerator, HalfGateEvaluator, HalfGateGenerator, InputLabel};

    #[test]
    fn garbled_circuit_test() {
        // m1 = 2^64 - 1
        let m1 = vec![true; 64];
        // m2 = 1
        let mut m2 = vec![false; 64];
        m2[0] = true;

        let res = vec![false; 64];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);
        assert_eq!(circ.nxor, 313);
        assert_eq!(circ.nand, 63);
        assert_eq!(circ.ninv, 0);

        let gen = HalfGateGenerator;
        let ev = HalfGateEvaluator;

        let complete_gc = gen.garble(&mut rng, &circ).unwrap();

        let generator_inputs: Vec<CircuitInput> = m1
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        let gc = complete_gc.to_public(&generator_inputs);

        let evaluator_input_labels: Vec<InputLabel> = m2
            .into_iter()
            .zip(complete_gc.input_labels[64..128].iter())
            .enumerate()
            .map(|(id, (value, label))| InputLabel {
                id: id + 64,
                label: label[value as usize],
            })
            .collect();

        let outputs = ev.eval(&circ, &gc, &evaluator_input_labels).unwrap();
        assert_eq!(outputs, res);
    }

    #[test]
    fn gc_aes_test() {
        let mut input = vec![false; 128];
        let mut key = vec![false; 128];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128_reverse.txt").unwrap();
        let gen = HalfGateGenerator;
        let ev = HalfGateEvaluator;

        let complete_gc = gen.garble(&mut rng, &circ).unwrap();

        key.reverse();
        input.reverse();

        let generator_inputs: Vec<CircuitInput> = input
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        let gc = complete_gc.to_public(&generator_inputs);

        let evaluator_input_labels: Vec<InputLabel> = key
            .into_iter()
            .zip(complete_gc.input_labels[128..256].iter())
            .enumerate()
            .map(|(id, (value, label))| InputLabel {
                id: id + 128,
                label: label[value as usize],
            })
            .collect();

        let mut outputs = ev.eval(&circ, &gc, &evaluator_input_labels).unwrap();
        outputs.reverse();
        assert_eq!(outputs.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

    }
}
