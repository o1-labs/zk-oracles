//! Define the trait of GC generator.

pub mod half_gate_gen;

pub use half_gate_gen::*;

use super::errors::GeneratorError;
use crate::{gc::GarbledCircuit, OutputDecodeInfo, WireLabel};
use circuit::Circuit;
use crypto_core::Block;
use rand::{CryptoRng, Rng};

pub trait GCGenerator {
    /// Generate a garbled circuit.
    fn garble<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        circ: &Circuit,
        input_zero_labels: &[WireLabel],
        data_to_mask: &Option<Vec<Vec<Block>>>,
    ) -> Result<(GarbledCircuit, Option<Vec<Vec<Block>>>), GeneratorError>;

    /// Compose to generate a new circuit.
    fn compose(
        &mut self,
        circ: &Circuit,
        labels: &Vec<WireLabel>,
        public_one_label: Block,
        data_to_mask: &Option<Vec<Vec<Block>>>,
    ) -> Result<(GarbledCircuit, Option<Vec<Vec<Block>>>), GeneratorError>;

    /// Finalize the GC generation.
    fn finalize(&self, output_zero_labels: &Vec<WireLabel>) -> Vec<OutputDecodeInfo>;
}
