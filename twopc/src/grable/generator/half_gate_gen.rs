use super::{GCGenerator, GeneratorError};
use crate::{
    GarbledCircuit, GarbledCircuitLocal, GarbledCircuitTable, InputValueLabel, InputZeroLabel,
    OutputDecodeInfo, OutputZeroLabel,
};
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
}

impl GCGenerator for HalfGateGenerator {
    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
        input_zero_labels: &[InputZeroLabel],
    ) -> Result<GarbledCircuit, GeneratorError> {
        assert_eq!(
            input_zero_labels.len(),
            circ.ninput_wires,
            "Input size not consistent!"
        );

        // Generate a random label for public 1.
        let public_one_label = rng.gen::<Block>() ^ self.delta;

        let mut table: Vec<[Block; 2]> = Vec::with_capacity(circ.nand);
        let mut wire_labels: Vec<Option<[Block; 2]>> = vec![None; circ.nwires];

        //Initiate input labels.
        for (wire, label) in wire_labels
            .iter_mut()
            .take(circ.ninput_wires)
            .zip(input_zero_labels.iter())
        {
            let z = [label.zero_label, label.zero_label ^ self.delta];
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

        let mut output_zero_labels: Vec<OutputZeroLabel> = Vec::with_capacity(circ.noutput_wires);

        for (id, wire) in (circ.nwires - circ.noutput_wires..circ.nwires)
            .zip(wire_labels.iter().skip(circ.nwires - circ.noutput_wires))
        {
            output_zero_labels.push(OutputZeroLabel {
                id,
                zero_label: wire.unwrap()[0],
            });
        }

        let gc_local = GarbledCircuitLocal::new(input_zero_labels.to_vec(), output_zero_labels);

        // let output_decode_info = gc_local.decode_info();
        let gc_table = GarbledCircuitTable::new(table, public_one_label);

        Ok(GarbledCircuit::new(gc_table, gc_local))
    }

    fn finalize(
        &self,
        gc_local: &GarbledCircuitLocal,
        inputs: &Vec<CircuitInput>,
    ) -> (Vec<InputValueLabel>, Vec<OutputDecodeInfo>) {
        (gc_local.encode(inputs, self.delta), gc_local.decode_info())
    }
}
