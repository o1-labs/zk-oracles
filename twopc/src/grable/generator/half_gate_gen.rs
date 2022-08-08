use super::{GCGenerator, GeneratorError};
use crate::CompleteGarbledCircuit;
use circuit::gate::{Circuit, Gate};
use crypto_core::{
    block::{Block, SELECT_MASK},
    AES_HASH,
};
use rand::{CryptoRng, Rng};

pub struct HalfGateGenerator;

impl HalfGateGenerator {
    #[inline]
    pub fn and_gate(
        &self,
        x: [Block; 2],
        y: [Block; 2],
        delta: Block,
        gid: usize,
    ) -> ([Block; 2], [Block; 2]) {
        let pa = x[0].lsb() as usize;
        let pb = y[0].lsb() as usize;

        let index = gid as u128;
        let index_next = (gid + 1) as u128;

        let hash_x0 = AES_HASH.tccr_hash(index.into(), x[0]);
        let hash_y0 = AES_HASH.tccr_hash(index_next.into(), y[0]);

        // First half gate: garbler knows pb
        let t_g = hash_x0 ^ AES_HASH.tccr_hash(index.into(), x[1]) ^ (SELECT_MASK[pb] & delta);
        // Output label w_g for wire 0
        let w_g = hash_x0 ^ (SELECT_MASK[pa] & t_g);

        // Second half gate: evaluator knows (pb xor b)
        let t_e = hash_y0 ^ AES_HASH.tccr_hash(index_next.into(), y[1]) ^ x[0];
        // Output label w_e for wire 0
        let w_e = hash_y0 ^ (SELECT_MASK[pb] & (t_e ^ x[0]));

        let z_0 = w_g ^ w_e;
        let z = [z_0, z_0 ^ delta];

        (z, [t_g, t_e])
    }

    #[inline]
    pub fn xor_gate(&self, x: [Block; 2], y: [Block; 2], delta: Block) -> [Block; 2] {
        let z_0 = x[0] ^ y[0];
        [z_0, z_0 ^ delta]
    }

    #[inline]
    pub fn inv_gate(&self, x: [Block; 2], public_one_label: Block, delta: Block) -> [Block; 2] {
        self.xor_gate(x, [public_one_label ^ delta, public_one_label], delta)
    }
}

impl GCGenerator for HalfGateGenerator {
    fn garble<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<CompleteGarbledCircuit, GeneratorError> {
        // Generate random delta
        let mut delta = rng.gen::<Block>();
        // Set delta lsb to 1
        delta = delta.set_lsb();

        // Generate a random label for public 1.
        let public_one_label = rng.gen::<Block>() ^ delta;

        let mut input_labels: Vec<[Block; 2]> = Vec::with_capacity(circ.ninput_wires);
        let mut table: Vec<[Block; 2]> = Vec::with_capacity(circ.nand);
        let mut wire_labels: Vec<Option<[Block; 2]>> = vec![None; circ.nwires];

        // Initiate input labels
        for wire in wire_labels.iter_mut().take(circ.ninput_wires) {
            let z_0 = rng.gen::<Block>();
            let z_1 = z_0 ^ delta;
            let z = [z_0, z_1];
            input_labels.push(z);
            *wire = Some(z);
        }

        // Process each gate
        let mut gid = 1;
        for gate in circ.gates.iter() {
            match *gate {
                Gate::Inv { lin_id, out_id, .. } => {
                    let x =
                        wire_labels[lin_id].ok_or(GeneratorError::UninitializedLabel(lin_id))?;

                    let z = self.inv_gate(x, public_one_label, delta);
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
                    let z = self.xor_gate(x, y, delta);
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
                    let (z, t) = self.and_gate(x, y, delta, gid);
                    table.push(t);
                    wire_labels[out_id] = Some(z);
                    gid += 1;
                }
            };
        }

        let mut output_bits: Vec<bool> = Vec::with_capacity(circ.noutput_wires);
        for wire in wire_labels.iter().skip(circ.nwires - circ.noutput_wires) {
            output_bits.push(wire.unwrap()[0].lsb());
        }

        Ok(CompleteGarbledCircuit::new(
            input_labels,
            wire_labels.into_iter().map(|w| w.unwrap()).collect(),
            table,
            output_bits,
            public_one_label,
            delta,
        ))
    }
}
