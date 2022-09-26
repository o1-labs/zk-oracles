pub mod half_gate_eval;

pub use half_gate_eval::*;

use super::errors::EvaluatorError;
use crate::{InputValueLabel, GarbledCircuitTable};
use circuit::Circuit;

pub trait GCEvaluator {
    /// Evaluate a garbled circuit
    fn eval(
        &mut self,
        circ: &Circuit,
        gc: &GarbledCircuitTable,
        input_value_labels: &[InputValueLabel],
    ) -> Result<Vec<bool>, EvaluatorError>;
}
