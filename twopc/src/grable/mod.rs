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
    use std::collections::HashMap;

    use circuit::{Circuit, CircuitInput};
    use crypto_core::{AesRng, Block};
    use rand::Rng;

    use crate::{
        encode, GCEvaluator, GCGenerator, HalfGateEvaluator, HalfGateGenerator, WireLabel,
    };

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

        // Set deta.
        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        // Generate random input zero labels.
        let input_zero_labels: Vec<WireLabel> = (0..circ.ninput_wires)
            .map(|id| WireLabel {
                id,
                label: rng.gen::<Block>(),
            })
            .collect();

        // Initiate half gate generator and evaluator.
        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        // Garbling the circuit.
        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        // Initiate the input from generator.
        let generator_inputs: Vec<CircuitInput> = m1
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        // Initiate the input from evaluator.
        let evaluator_inputs: Vec<CircuitInput> = m2
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 64,
                value: Block::from(value as u128),
            })
            .collect();

        // Concatenate the two inputs.
        let inputs = [generator_inputs, evaluator_inputs].concat();

        // Encode the inputs into labels with zero labels.
        let input_value_labels = encode(&input_zero_labels, &inputs, delta);

        // Generate the decoding information.
        let output_decode_info = gen.finalize(&gc.output_zero_labels);

        // The evaluator evaluates the garbled circuit and gets the output value labels.
        let output_value_labels = ev.eval(&circ, &gc.gc_table, &input_value_labels).unwrap();

        // The evaluator decode the output value labels into output bool vectors.
        let outputs = ev.finalize(&output_value_labels, &output_decode_info);

        assert_eq!(outputs, res);
    }

    #[test]
    fn gc_aes_test() {
        let key = vec![true; 128];
        let input = vec![false; 128];
        let mut rng = AesRng::new();

        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128.txt").unwrap();

        // Set deta.
        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        // Generate random input zero labels.
        let input_zero_labels: Vec<WireLabel> = (0..circ.ninput_wires)
            .map(|id| WireLabel {
                id,
                label: rng.gen::<Block>(),
            })
            .collect();

        // Initiate half gate generator and evaluator.
        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        // Garbling the circuit.
        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        // Initiate the input from generator.
        let generator_inputs: Vec<CircuitInput> = input
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        // Initiate the input from evaluator.
        let evaluator_inputs: Vec<CircuitInput> = key
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 128,
                value: Block::from(value as u128),
            })
            .collect();

        // Concatenate the two inputs.
        let inputs = [generator_inputs, evaluator_inputs].concat();

        // Encode the inputs into labels with zero labels.
        let input_value_labels = encode(&input_zero_labels, &inputs, delta);

        // Generate the decoding information.
        let output_decode_info = gen.finalize(&gc.output_zero_labels);

        // The evaluator evaluates the garbled circuit and gets the output value labels.
        let output_value_labels = ev.eval(&circ, &gc.gc_table, &input_value_labels).unwrap();

        // The evaluator decode the output value labels into output bool vectors.
        let outputs = ev.finalize(&output_value_labels, &output_decode_info);

        assert_eq!(outputs.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
            "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");
    }

    #[test]
    fn gc_compose_adder64_test() {
        // Compose m1 + m2 + m3

        // m1 = 2^64 -1
        let m1 = vec![true; 64];
        // m2 = 1
        let mut m2 = vec![false; 64];
        m2[0] = true;
        // m3 = 1
        let mut m3 = vec![false; 64];
        m3[0] = true;
        // res = 1
        let mut res = vec![false; 64];
        res[0] = true;

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);
        assert_eq!(circ.nxor, 313);
        assert_eq!(circ.nand, 63);
        assert_eq!(circ.ninv, 0);

        // Set delta.
        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        // Generate random input zero labels.
        let input_zero_labels: Vec<WireLabel> = (0..circ.ninput_wires)
            .map(|id| WireLabel {
                id,
                label: rng.gen::<Block>(),
            })
            .collect();

        // Map the output wires of the first adder64 circuit into the first 64 input wires of the second adder64 circuit.
        let mut map = HashMap::<usize, usize>::new();
        for i in circ.nwires - circ.noutput_wires..circ.nwires {
            map.insert(i, i - (circ.nwires - circ.noutput_wires));
        }

        for i in 64..128 {
            map.insert(i, i);
        }

        let indicator = Some(map);

        // Generate random input zero labels for m3
        let m3_zero_labels: Vec<WireLabel> = (0..64)
            .map(|id| WireLabel {
                id: id + 64,
                label: rng.gen::<Block>(),
            })
            .collect();

        // Initiate half gate generator and evaluator.
        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        // Garbling the first add64 circuit for m1 + m2.
        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        // Concatnenate the output zero labels of m1+m2 and input zero labels of m3.
        let mut m1m2m3_zero_labels =
            [gc.clone().output_zero_labels, m3_zero_labels.clone()].concat();

        // Compose the add64 gate associated with m3.
        let composed_gc = gen
            .compose(&circ, &mut m1m2m3_zero_labels, gc.gc_table.public_one_label)
            .unwrap();

        // Generate the decoding information of composed circuits.
        let output_decode_info = gen.finalize(&composed_gc.output_zero_labels);

        // Initiate the input of m1.
        let m1_inputs: Vec<CircuitInput> = m1
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        // Initiate the input of m2.
        let m2_inputs: Vec<CircuitInput> = m2
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 64,
                value: Block::from(value as u128),
            })
            .collect();

        // Initiate the input of m3.
        let m3_inputs: Vec<CircuitInput> = m3
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 64,
                value: Block::from(value as u128),
            })
            .collect();

        // Concatenate the m1 and m2 inputs.
        let m1m2_inputs = [m1_inputs, m2_inputs].concat();

        // Encode m1||m2 inputs into labels.
        let m1m2_value_labels = encode(&input_zero_labels, &m1m2_inputs, delta);

        // Evaluate the first add64 circuit.
        let m1m2_output_labels = ev.eval(&circ, &gc.gc_table, &m1m2_value_labels).unwrap();

        // Encode m3 inputs into labels
        let m3_input_labels = encode(&m3_zero_labels, &m3_inputs, delta);

        // Concatenate the m1+m2 output labels and the m3 input labels
        let m1m2m3_input_labels = [m1m2_output_labels, m3_input_labels].concat();

        // Evaluate composed garbled circuit.
        let m1m2m3_value_labels = ev
            .compose(
                &circ,
                &composed_gc.gc_table,
                &m1m2m3_input_labels,
                &indicator,
            )
            .unwrap();

        // Decode the labels into bool vectors.
        let outputs = ev.finalize(&m1m2m3_value_labels, &output_decode_info);

        assert_eq!(outputs, res);
    }

    #[test]
    fn gc_compose_aes_test() {
        // Compose AES(AES(m,K),K)

        let m = vec![true; 128];
        let key = vec![true; 128];

        let mut rng = AesRng::new();
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128.txt").unwrap();

        // Set delta.
        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        // Generate random input zero labels.
        let input_zero_labels: Vec<WireLabel> = (0..circ.ninput_wires)
            .map(|id| WireLabel {
                id,
                label: rng.gen::<Block>(),
            })
            .collect();

        // Map the output wires of the first AES circuit into the first 128 input wires of the second AES128 circuit.
        let mut map = HashMap::<usize, usize>::new();
        for i in circ.nwires - circ.noutput_wires..circ.nwires {
            map.insert(i, i - (circ.nwires - circ.noutput_wires));
        }

        for i in 128..256 {
            map.insert(i, i);
        }

        let indicator = Some(map);

        // Initiate half gate generator and evaluator.
        let mut gen = HalfGateGenerator::new(delta);
        let mut ev = HalfGateEvaluator::new();

        // Garbling the first AES circuit for c = AES(K,m).
        let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();

        // Concatenate the output zero labels of c and input zero labels of key.
        let mut c_key_zero_labels = [
            gc.output_zero_labels.clone(),
            input_zero_labels[128..256].to_vec().clone(),
        ]
        .concat();

        // Compose AES(K,c).
        let composed_gc = gen
            .compose(&circ, &mut c_key_zero_labels, gc.gc_table.public_one_label)
            .unwrap();

        // Generate the decoding information of composed circuits.
        let output_decode_info = gen.finalize(&composed_gc.output_zero_labels);

        // Initiate the input of m.
        let m_inputs: Vec<CircuitInput> = m
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id,
                value: Block::from(value as u128),
            })
            .collect();

        // Initiate the input of key.
        let key_inputs: Vec<CircuitInput> = key
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput {
                id: id + 128,
                value: Block::from(value as u128),
            })
            .collect();

        // Concatenate the m and key inputs.
        let m_key_inputs = [m_inputs, key_inputs].concat();

        // Encode m||key inputs into labels.
        let m_key_value_labels = encode(&input_zero_labels, &m_key_inputs, delta);

        // Evaluate the first AES circuit of c = AES(m,key).
        let c_output_labels = ev.eval(&circ, &gc.gc_table, &m_key_value_labels).unwrap();

        // Extract key value labels
        let key_value_labels = m_key_value_labels[128..256].to_vec();

        // Concatenate the c output labels and the key value labels
        let c_key_value_labels = [c_output_labels, key_value_labels].concat();

        // Evaluate composed garbled circuit.
        let output_value_labels = ev
            .compose(
                &circ,
                &composed_gc.gc_table,
                &c_key_value_labels,
                &indicator,
            )
            .unwrap();

        // Decode the labels into bool vectors.
        let outputs = ev.finalize(&output_value_labels, &output_decode_info);

        assert_eq!(outputs.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
            "01100000101111000110001000100100110111101000100000110100011001101010101010011011100011000111000000010111001000000111000011000011");
    }
}
