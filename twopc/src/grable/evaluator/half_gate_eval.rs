use std::collections::HashMap;

use crate::{EvaluatorError, GCEvaluator, GarbledCircuitTable, OutputDecodeInfo, WireLabel};
use circuit::gate::Gate;
use circuit::Circuit;
use crypto_core::{block::SELECT_MASK, Block, AES_HASH};

#[derive(Clone)]
pub struct HalfGateEvaluator {
    counter: u128,
}

impl HalfGateEvaluator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    #[inline]
    pub fn and_gate(&mut self, x: Block, y: Block, table: [Block; 2]) -> Block {
        let sa = x.lsb() as usize;
        let sb = y.lsb() as usize;

        let index = self.counter;
        self.counter = self.counter + 1;
        let index_next = self.counter;
        self.counter = self.counter + 1;

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

    pub(crate) fn eval_core(
        &mut self,
        circ: &Circuit,
        gc_table: &GarbledCircuitTable,
        input_value_labels: &[WireLabel],
        indicator: &Option<HashMap<usize, usize>>,
    ) -> Result<Vec<WireLabel>, EvaluatorError> {
        assert_eq!(
            input_value_labels.len(),
            circ.ninput_wires,
            "Number of input wires is not consistent!"
        );

        let mut wire_labels: Vec<Option<Block>> = vec![None; circ.nwires];

        match indicator {
            None => {
                for label in input_value_labels {
                    wire_labels[label.id] = Some(label.label);
                }
            }

            Some(idx) => {
                for label in input_value_labels {
                    wire_labels[*idx.get(&label.id).unwrap()] = Some(label.label);
                }
            }
        };

        let mut gid = 0;
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { lin_id, out_id, .. } => {
                    let x =
                        wire_labels[lin_id].ok_or(EvaluatorError::UninitializedLabel(lin_id))?;
                    let z = self.inv_gate(x, gc_table.public_one_label);

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
                    let z = self.and_gate(x, y, gc_table.table[gid]);

                    wire_labels[out_id] = Some(z);
                    gid += 1;
                }
            };
        }

        let outputs = wire_labels
            .iter()
            .skip(circ.nwires - circ.noutput_wires)
            .zip(circ.nwires - circ.noutput_wires..circ.nwires)
            .map(|(x, id)| WireLabel {
                id,
                label: x.unwrap(),
            })
            .collect();

        Ok(outputs)
    }
}

impl GCEvaluator for HalfGateEvaluator {
    fn eval(
        &mut self,
        circ: &Circuit,
        gc_table: &GarbledCircuitTable,
        input_value_labels: &[WireLabel],
    ) -> Result<Vec<WireLabel>, EvaluatorError> {
        assert_eq!(
            input_value_labels.len(),
            circ.ninput_wires,
            "Number of input wires is not consistent!"
        );

        let output_labels = self.eval_core(&circ, &gc_table, &input_value_labels, &None);

        output_labels
    }

    fn compose(
        &mut self,
        circ: &circuit::Circuit,
        gc_table: &GarbledCircuitTable,
        output_value_labels: &[WireLabel],
        indicator: &Option<HashMap<usize, usize>>,
    ) -> Result<Vec<WireLabel>, EvaluatorError> {
        assert_eq!(
            output_value_labels.len(),
            circ.ninput_wires,
            "Number of input wires is not consistent!"
        );

        let output_labels = self.eval_core(&circ, &gc_table, &output_value_labels, indicator);

        output_labels
    }

    fn finalize(
        &self,
        out_labels: &Vec<WireLabel>,
        decode_info: &Vec<OutputDecodeInfo>,
    ) -> Vec<bool> {
        decode(out_labels, decode_info)
    }
}

pub fn decode(labels: &Vec<WireLabel>, decode_info: &Vec<OutputDecodeInfo>) -> Vec<bool> {
    assert_eq!(labels.len(), decode_info.len(), "lenght is not consistent!");
    labels
        .iter()
        .zip(decode_info.iter())
        .map(|(x, y)| {
            if x.id == y.id {
                x.label.lsb() ^ y.decode_info
            } else {
                panic!("Id not consistent!");
            }
        })
        .collect()
}
