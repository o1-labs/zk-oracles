pub mod half_gate_eval;

pub use half_gate_eval::*;

use crate::errors::EvaluatorError;
use crate::gc::{GarbledCircuit, InputLabel};
use circuit::Circuit;

pub trait GCEvaluator {
    /// Evaluate a garbled circuit
    fn eval(
        &self,
        circ: &Circuit,
        gc: &GarbledCircuit,
        evaluator_input_labels: &[InputLabel],
    ) -> Result<Vec<bool>, EvaluatorError>;
}
