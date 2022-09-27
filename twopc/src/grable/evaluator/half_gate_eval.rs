use crate::{
    EvaluatorError, GCEvaluator, GarbledCircuitTable, InputValueLabel, OutputDecodeInfo,
    OutputValueLabel,
};
use circuit::gate::Gate;
use crypto_core::{block::SELECT_MASK, Block, AES_HASH};

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
}

impl GCEvaluator for HalfGateEvaluator {
    fn eval(
        &mut self,
        circ: &circuit::Circuit,
        gc: &GarbledCircuitTable,
        input_value_labels: &[InputValueLabel],
    ) -> Result<Vec<OutputValueLabel>, EvaluatorError> {
        assert_eq!(
            input_value_labels.len(),
            circ.ninput_wires,
            "Number of input wires is not consistent!"
        );

        let mut wire_labels: Vec<Option<Block>> = vec![None; circ.nwires];

        for label in input_value_labels {
            wire_labels[label.id] = Some(label.label);
        }

        let mut gid = self.counter as usize;
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
                    let z = self.and_gate(x, y, gc.table[gid]);

                    wire_labels[out_id] = Some(z);
                    gid += 1;
                }
            };
        }

        let outputs = wire_labels
            .iter()
            .skip(circ.nwires - circ.noutput_wires)
            .zip(circ.nwires - circ.noutput_wires..circ.nwires)
            .map(|(x, id)| OutputValueLabel {
                id,
                label: x.unwrap(),
            })
            .collect();

        Ok(outputs)
    }

    fn finalize(
        &self,
        out_labels: &Vec<OutputValueLabel>,
        decode_info: &Vec<OutputDecodeInfo>,
    ) -> Vec<bool> {
        out_labels
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
}
