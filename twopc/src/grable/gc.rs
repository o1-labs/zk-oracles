//! Define the struct of garbled circuit.
//! Part of the code is derived form TLSNotary.

use circuit::CircuitInput;
use crypto_core::block::Block;

#[derive(Debug, Clone, Copy)]
pub struct InputValueLabel {
    /// Input wire id
    pub id: usize,
    /// Input wire label according to the value
    pub label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputValueLabel {
    /// Output wire id
    pub id: usize,
    /// Output wire label according to the value
    pub label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct InputZeroLabel {
    /// Input wire id
    pub id: usize,
    /// Input wire zero label
    pub zero_label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputZeroLabel {
    /// Output wire id
    pub id: usize,
    /// Output wire zero label
    pub zero_label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputDecodeInfo {
    /// Output wire id
    pub id: usize,
    /// Output decode info
    pub decode_info: bool,
}

/// garbled tables and related info (independent of the inputs) sent to the evaluator.
#[derive(Debug, Clone)]
pub struct GarbledCircuitTable {
    pub table: Vec<[Block; 2]>,
    pub public_one_label: Block,
}

impl GarbledCircuitTable {
    pub fn new(table: Vec<[Block; 2]>, public_one_label: Block) -> Self {
        Self {
            table,
            public_one_label,
        }
    }
}

/// Informaiton used in garbled circuit, and only hold by the generator.
#[derive(Debug, Clone)]
pub struct GarbledCircuitLocal {
    pub input_zero_labels: Vec<InputZeroLabel>,
    pub output_zero_labels: Vec<OutputZeroLabel>,
}

impl GarbledCircuitLocal {
    pub fn new(
        input_zero_labels: Vec<InputZeroLabel>,
        output_zero_labels: Vec<OutputZeroLabel>,
    ) -> Self {
        Self {
            input_zero_labels,
            output_zero_labels,
        }
    }

    pub fn encode(&self, inputs: &Vec<CircuitInput>, delta: Block) -> Vec<InputValueLabel> {
        assert_eq!(inputs.len(), self.input_zero_labels.len());

        self.input_zero_labels
            .iter()
            .zip(inputs.iter())
            .map(|(x, y)| {
                if y.value.lsb() ^ (x.id == y.id) {
                    InputValueLabel {
                        id: x.id,
                        label: x.zero_label,
                    }
                } else if x.id == y.id {
                    InputValueLabel {
                        id: x.id,
                        label: x.zero_label ^ delta,
                    }
                } else {
                    panic!("Id not consistent!");
                }
            })
            .collect()
    }

    pub fn decode_info(&self) -> Vec<OutputDecodeInfo> {
        self.output_zero_labels
            .iter()
            .map(|x| OutputDecodeInfo {
                id: x.id,
                decode_info: x.zero_label.lsb(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub gc_table: GarbledCircuitTable,
    pub gc_local: GarbledCircuitLocal,
}

impl GarbledCircuit {
    pub fn new(gc_table: GarbledCircuitTable, gc_local: GarbledCircuitLocal) -> Self {
        Self { gc_table, gc_local }
    }
}
