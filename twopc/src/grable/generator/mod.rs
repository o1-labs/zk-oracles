pub mod half_gate_gen;

pub use half_gate_gen::*;

use super::errors::GeneratorError;
use crate::{
    gc::GarbledCircuit, GarbledCircuitLocal, InputValueLabel, InputZeroLabel, OutputDecodeInfo,
};
use circuit::{Circuit, CircuitInput};
use rand::{CryptoRng, Rng};

pub trait GCGenerator {
    /// Generate a garbled circuit
    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
        input_zero_labels: &[InputZeroLabel],
    ) -> Result<GarbledCircuit, GeneratorError>;

    fn compose() {}

    fn finalize(
        &self,
        gc_local: &GarbledCircuitLocal,
        inputs: &Vec<CircuitInput>,
    ) -> (Vec<InputValueLabel>, Vec<OutputDecodeInfo>);
}
