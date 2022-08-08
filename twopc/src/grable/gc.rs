//! Define the struct of garbled circuit.
//! Part of the code is derived form TLSNotary.

use circuit::CircuitInput;
use crypto_core::block::Block;

#[derive(Debug, Clone, Copy)]
pub struct InputLabel {
    /// Input wire label id
    pub id: usize,
    // Input wire label
    pub label: Block,
}

/// Complete garbled circuit data, including private data which should not be revealed
/// to the evaluator
#[derive(Debug, Clone)]
pub struct CompleteGarbledCircuit {
    pub input_labels: Vec<[Block; 2]>,
    pub wire_labels: Vec<[Block; 2]>,
    pub table: Vec<[Block; 2]>,
    pub output_bits: Vec<bool>,
    pub public_one_label: Block,
    pub delta: Block,
}

/// Garbled circuit data safe to share with evaluator
#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    /// Wire labels corresponding to the generators input bits
    pub generator_input_labels: Vec<InputLabel>,
    /// Truth table for garbled AND gates
    pub table: Vec<[Block; 2]>,
    /// Wire labels corresponding to public one
    /// public_one_label = random_label xor delta
    pub public_one_label: Block,
    /// LSBs of output labels
    pub output_bits: Vec<bool>,
}

impl CompleteGarbledCircuit {
    pub fn new(
        input_labels: Vec<[Block; 2]>,
        wire_labels: Vec<[Block; 2]>,
        table: Vec<[Block; 2]>,
        output_bits: Vec<bool>,
        public_one_label: Block,
        delta: Block,
    ) -> Self {
        Self {
            input_labels,
            wire_labels,
            table,
            output_bits,
            public_one_label,
            delta,
        }
    }

    /// Converts `CompleteGarbledCircuit` to `GarbledCircuit` which is safe to share with the evaluator
    pub fn to_public(&self, inputs: &[CircuitInput]) -> GarbledCircuit {
        let mut generator_input_labels = Vec::with_capacity(inputs.len());
        for input in inputs.iter() {
            generator_input_labels.push(InputLabel {
                id: input.id,
                label: self.input_labels[input.id][input.value.lsb() as usize],
            });
        }
        GarbledCircuit {
            generator_input_labels,
            table: self.table.clone(),
            output_bits: self.output_bits.clone(),
            public_one_label: self.public_one_label,
        }
    }
}
