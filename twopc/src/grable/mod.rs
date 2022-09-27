pub mod errors;
pub mod evaluator;
pub mod gc;
pub mod generator;

pub use errors::*;
pub use evaluator::*;
pub use gc::*;
pub use generator::*;

#[cfg(test)]
mod tests {
    use circuit::{Circuit, CircuitInput};
    use crypto_core::{AesRng, Block};
    use rand::Rng;

    use crate::{GCEvaluator, GCGenerator, HalfGateEvaluator, HalfGateGenerator, InputZeroLabel};

    #[test]
    fn gc_adder64_test() {
        // m1 = 2^64 - 1
        let m1 = vec![true; 64];
        // m2 = 1
        let mut m2 = vec![false; 64];
        m2[0] = true;

        let res = vec![false; 64];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);
        assert_eq!(circ.nxor, 313);
        assert_eq!(circ.nand, 63);
        assert_eq!(circ.ninv, 0);

        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        let input_zero_labels: Vec<InputZeroLabel> = (0..circ.ninput_wires)
            .map(|id| InputZeroLabel {
                id,
                zero_label: rng.gen::<Block>(),
            })
            .collect();

        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        let generator_inputs: Vec<CircuitInput> = m1
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        let evaluator_inputs: Vec<CircuitInput> = m2
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 64,
                value: Block::from(value as u128),
            })
            .collect();

        let inputs = [generator_inputs, evaluator_inputs].concat();

        let (input_value_labels, output_decode_info) = gen.finalize(&gc.gc_local, &inputs);

        let output_value_labels = ev.eval(&circ, &gc.gc_table, &input_value_labels).unwrap();

        let outputs = ev.finalize(&output_value_labels, &output_decode_info);

        assert_eq!(outputs, res);
    }

    #[test]
    fn gc_aes_test() {
        let mut input = vec![false; 128];
        let mut key = vec![false; 128];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128_reverse.txt").unwrap();
        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        let input_zero_labels: Vec<InputZeroLabel> = (0..circ.ninput_wires)
            .map(|id| InputZeroLabel {
                id,
                zero_label: rng.gen::<Block>(),
            })
            .collect();

        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        key.reverse();
        input.reverse();

        let generator_inputs: Vec<CircuitInput> = input
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        let evaluator_inputs: Vec<CircuitInput> = key
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 128,
                value: Block::from(value as u128),
            })
            .collect();

        let inputs = [generator_inputs, evaluator_inputs].concat();

        let (input_value_labels, output_decode_info) = gen.finalize(&gc.gc_local, &inputs);

        let output_value_labels = ev.eval(&circ, &gc.gc_table, &input_value_labels).unwrap();

        let mut outputs = ev.finalize(&output_value_labels, &output_decode_info);

        // let input_value_labels = gc.gc_local.encode(&inputs);

        // let mut outputs = ev.eval(&circ, &gc.gc_table, &input_value_labels).unwrap();

        outputs.reverse();
        assert_eq!(outputs.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");
    }
}
