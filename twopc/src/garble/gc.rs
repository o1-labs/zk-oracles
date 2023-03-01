//! Define the struct of garbled circuit.

use crypto_core::block::Block;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WireLabel {
    /// wire id
    pub id: usize,
    ///  wire label
    pub label: Block,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OutputDecodeInfo {
    /// Output wire id
    pub id: usize,
    /// Output decode info
    pub decode_info: bool,
}

/// garbled tables and related info (independent of the inputs) sent to the evaluator.
#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct GarbledCircuit {
    pub gc_table: GarbledCircuitTable,
    pub output_zero_labels: Vec<WireLabel>,
}

impl GarbledCircuit {
    pub fn new(gc_table: GarbledCircuitTable, output_zero_labels: Vec<WireLabel>) -> Self {
        Self {
            gc_table,
            output_zero_labels,
        }
    }
}
