pub mod half_gate_gen;

pub use half_gate_gen::*;

use crate::errors::GeneratorError;
use crate::gc::CompleteGarbledCircuit;
use circuit::Circuit;
use rand::{CryptoRng, Rng};

pub trait GCGenerator {
    /// Generate a garbled circuit
    fn garble<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        circ: &Circuit,
    ) -> Result<CompleteGarbledCircuit, GeneratorError>;
}
