pub mod half_gate_eval;

use std::collections::HashMap;

pub use half_gate_eval::*;

use super::errors::EvaluatorError;
use crate::{GarbledCircuitTable, OutputDecodeInfo, WireLabel};
use circuit::Circuit;

pub trait GCEvaluator {
    /// Evaluate a garbled circuit.
    fn eval(
        &mut self,
        circ: &Circuit,
        gc_table: &GarbledCircuitTable,
        input_value_labels: &[WireLabel],
    ) -> Result<Vec<WireLabel>, EvaluatorError>;

    /// Compose to evaluate a new circuit.
    fn compose(
        &mut self,
        circ: &Circuit,
        gc_table: &GarbledCircuitTable,
        output_value_labels: &[WireLabel],
        indicator: &Option<HashMap<usize, usize>>,
    ) -> Result<Vec<WireLabel>, EvaluatorError>;

    /// Finalize GC evaluation.
    fn finalize(
        &self,
        out_labels: &Vec<WireLabel>,
        decode_info: &Vec<OutputDecodeInfo>,
    ) -> Vec<bool>;
}
