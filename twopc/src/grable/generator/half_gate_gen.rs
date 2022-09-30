use super::{GCGenerator, GeneratorError};
use crate::{GarbledCircuit, GarbledCircuitTable, OutputDecodeInfo, WireLabel};
use circuit::{
    gate::{Circuit, Gate},
    CircuitInput,
};
use crypto_core::{
    block::{Block, SELECT_MASK},
    AES_HASH,
};
use rand::{CryptoRng, Rng};

pub struct HalfGateGenerator {
    counter: u128,
    delta: Block,
}

impl HalfGateGenerator {
    pub fn new(delta: Block) -> Self {
        Self { counter: 0, delta }
    }

    #[inline]
    pub fn and_gate(&mut self, x: [Block; 2], y: [Block; 2]) -> ([Block; 2], [Block; 2]) {
        let pa = x[0].lsb() as usize;
        let pb = y[0].lsb() as usize;

        let index = self.counter;
        self.counter = self.counter + 1;
        let index_next = self.counter;
        self.counter = self.counter + 1;

        let hash_x0 = AES_HASH.tccr_hash(index.into(), x[0]);
        let hash_y0 = AES_HASH.tccr_hash(index_next.into(), y[0]);

        // First half gate: garbler knows pb
        let t_g = hash_x0 ^ AES_HASH.tccr_hash(index.into(), x[1]) ^ (SELECT_MASK[pb] & self.delta);
        // Output label w_g for wire 0
        let w_g = hash_x0 ^ (SELECT_MASK[pa] & t_g);

        // Second half gate: evaluator knows (pb xor b)
        let t_e = hash_y0 ^ AES_HASH.tccr_hash(index_next.into(), y[1]) ^ x[0];
        // Output label w_e for wire 0
        let w_e = hash_y0 ^ (SELECT_MASK[pb] & (t_e ^ x[0]));

        let z_0 = w_g ^ w_e;
        let z = [z_0, z_0 ^ self.delta];

        (z, [t_g, t_e])
    }

    #[inline]
    pub fn xor_gate(&self, x: [Block; 2], y: [Block; 2]) -> [Block; 2] {
        let z_0 = x[0] ^ y[0];
        [z_0, z_0 ^ self.delta]
    }

    #[inline]
    pub fn inv_gate(&self, x: [Block; 2], public_one_label: Block) -> [Block; 2] {
        self.xor_gate(x, [public_one_label ^ self.delta, public_one_label])
    }

    pub fn gen_core(
        &mut self,
        circ: &Circuit,
        input_zero_labels: &[WireLabel],
        public_one_label: Block,
    ) -> Result<(Vec<[Block; 2]>, Vec<WireLabel>), GeneratorError> {
        assert_eq!(
            input_zero_labels.len(),
            circ.ninput_wires,
            "Input size not consistent!"
        );

        let mut table: Vec<[Block; 2]> = Vec::with_capacity(circ.nand);
        let mut wire_labels: Vec<Option<[Block; 2]>> = vec![None; circ.nwires];

        //Initiate input labels.
        for (wire, label) in wire_labels
            .iter_mut()
            .take(circ.ninput_wires)
            .zip(input_zero_labels.iter())
        {
            let z = [label.label, label.label ^ self.delta];
            *wire = Some(z);
        }

        // Process each gate
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { lin_id, out_id, .. } => {
                    let x =
                        wire_labels[lin_id].ok_or(GeneratorError::UninitializedLabel(lin_id))?;

                    let z = self.inv_gate(x, public_one_label);
                    wire_labels[out_id] = Some(z);
                }
                Gate::Xor {
                    lin_id,
                    rin_id,
                    out_id,
                    ..
                } => {
                    let x =
                        wire_labels[lin_id].ok_or(GeneratorError::UninitializedLabel(lin_id))?;
                    let y =
                        wire_labels[rin_id].ok_or(GeneratorError::UninitializedLabel(rin_id))?;
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
                        wire_labels[lin_id].ok_or(GeneratorError::UninitializedLabel(lin_id))?;
                    let y =
                        wire_labels[rin_id].ok_or(GeneratorError::UninitializedLabel(rin_id))?;
                    let (z, t) = self.and_gate(x, y);
                    table.push(t);
                    wire_labels[out_id] = Some(z);
                }
            };
        }

        let mut output_zero_labels: Vec<WireLabel> = Vec::with_capacity(circ.noutput_wires);

        for (id, wire) in (circ.nwires - circ.noutput_wires..circ.nwires)
            .zip(wire_labels.iter().skip(circ.nwires - circ.noutput_wires))
        {
            output_zero_labels.push(WireLabel {
                id,
                label: wire.unwrap()[0],
            });
        }

        Ok((table, output_zero_labels))
    }
}

impl GCGenerator for HalfGateGenerator {
    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
        input_zero_labels: &[WireLabel],
    ) -> Result<GarbledCircuit, GeneratorError> {
        // Generate a random label for public 1.
        let public_one_label = rng.gen::<Block>() ^ self.delta;

        let (table, output_zero_labels) =
            self.gen_core(&circ, &input_zero_labels, public_one_label)?;

        let gc_table = GarbledCircuitTable::new(table, public_one_label);

        Ok(GarbledCircuit::new(gc_table, output_zero_labels))
    }

    fn compose(
        &mut self,
        circ: &Circuit,
        output_zero_labels: &Vec<WireLabel>,
        public_one_label: Block,
    ) -> Result<GarbledCircuit, GeneratorError> {
        assert_eq!(
            output_zero_labels.len(),
            circ.ninput_wires,
            "Input and outputs sizes are not consistent!"
        );

        let (table, output_labels) = self
            .gen_core(&circ, &output_zero_labels, public_one_label)
            .unwrap();

        let gc_table = GarbledCircuitTable::new(table, public_one_label);

        Ok(GarbledCircuit::new(gc_table, output_labels))
    }

    fn finalize(&self, output_zero_labels: &Vec<WireLabel>) -> Vec<OutputDecodeInfo> {
        decode_info(output_zero_labels)
    }
}

pub fn encode(labels: &Vec<WireLabel>, inputs: &Vec<CircuitInput>, delta: Block) -> Vec<WireLabel> {
    assert_eq!(inputs.len(), labels.len());

    labels
        .iter()
        .zip(inputs.iter())
        .map(|(x, y)| {
            if y.value.lsb() ^ (x.id == y.id) {
                WireLabel {
                    id: x.id,
                    label: x.label,
                }
            } else if x.id == y.id {
                WireLabel {
                    id: x.id,
                    label: x.label ^ delta,
                }
            } else {
                panic!("Id not consistent!");
            }
        })
        .collect()
}

pub fn decode_info(labels: &Vec<WireLabel>) -> Vec<OutputDecodeInfo> {
    labels
        .iter()
        .map(|x| OutputDecodeInfo {
            id: x.id,
            decode_info: x.label.lsb(),
        })
        .collect()
}
