pub mod half_gate_eval;

pub use half_gate_eval::*;

use super::errors::EvaluatorError;
use crate::{GarbledCircuitTable, InputValueLabel, OutputDecodeInfo, OutputValueLabel};
use circuit::Circuit;

pub trait GCEvaluator {
    /// Evaluate a garbled circuit
    fn eval(
        &mut self,
        circ: &Circuit,
        gc: &GarbledCircuitTable,
        input_value_labels: &[InputValueLabel],
    ) -> Result<Vec<OutputValueLabel>, EvaluatorError>;

    fn compose() {}

    fn finalize(
        &self,
        out_labels: &Vec<OutputValueLabel>,
        decode_info: &Vec<OutputDecodeInfo>,
    ) -> Vec<bool>;
}
