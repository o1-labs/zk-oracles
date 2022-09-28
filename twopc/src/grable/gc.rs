//! Define the struct of garbled circuit.
//! Part of the code is derived form TLSNotary.

use circuit::CircuitInput;
use crypto_core::block::Block;

#[derive(Debug, Clone, Copy)]
pub struct WireLabel {
    /// wire id
    pub id: usize,
    ///  wire label
    pub label: Block,
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
    pub input_zero_labels: Vec<WireLabel>,
    pub output_zero_labels: Vec<WireLabel>,
}

impl GarbledCircuitLocal {
    pub fn new(
        input_zero_labels: Vec<WireLabel>,
        output_zero_labels: Vec<WireLabel>,
    ) -> Self {
        Self {
            input_zero_labels,
            output_zero_labels,
        }
    }

    pub fn encode(&self, inputs: &Vec<CircuitInput>, delta: Block) -> Vec<WireLabel> {
        assert_eq!(inputs.len(), self.input_zero_labels.len());

        self.input_zero_labels
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

    pub fn decode_info(&self) -> Vec<OutputDecodeInfo> {
        self.output_zero_labels
            .iter()
            .map(|x| OutputDecodeInfo {
                id: x.id,
                decode_info: x.label.lsb(),
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
