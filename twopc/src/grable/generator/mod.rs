pub mod half_gate_gen;

pub use half_gate_gen::*;

use super::errors::GeneratorError;
use crate::gc::GarbledCircuit;
use circuit::Circuit;
use rand::{CryptoRng, Rng};

pub trait GCGenerator {
    /// Generate a garbled circuit
    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<GarbledCircuit, GeneratorError>;
}
