//! Define the struct of garbled circuit.
//! Part of the code is derived form TLSNotary.

use circuit::CircuitInput;
use crypto_core::block::Block;

#[derive(Debug, Clone, Copy)]
pub struct InputValueLabel {
    /// Input wire id
    pub id: usize,
    /// Input wire label according to the value
    pub label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct InputZeroLabel {
    /// Input wire id
    pub id: usize,
    /// Input wire zero label
    pub zero_label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputZeroLabel {
    /// Output wire id
    pub id: usize,
    /// Output wire zero label
    pub zero_label: Block,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputDecodeInfo {
    /// Output wire id
    pub id: usize,
    /// Output decode info
    pub decode_info: bool,
}

/// garbled tables and related info sent to the evaluator.
#[derive(Debug, Clone)]
pub struct GarbledCircuitTable {
//    pub input_value_labels: Vec<InputValueLabel>,
    pub table: Vec<[Block; 2]>,
    pub output_decode_info: Vec<OutputDecodeInfo>,
    pub public_one_label: Block,
}

impl GarbledCircuitTable {
    pub fn new(
 //       input_value_labels: Vec<InputValueLabel>,
        table: Vec<[Block; 2]>,
        output_decode_info: Vec<OutputDecodeInfo>,
        public_one_label: Block,
    ) -> Self {
        Self {
//            input_value_labels,
            table,
            output_decode_info,
            public_one_label,
        }
    }
}

/// informaiton used in garbled circuit, and only hold by the generator.
#[derive(Debug, Clone)]
pub struct GarbledCircuitLocal {
    pub input_zero_labels: Vec<InputZeroLabel>,
    pub output_zero_labels: Vec<OutputZeroLabel>,
    pub delta: Block,
}

impl GarbledCircuitLocal {
    pub fn new(
        input_zero_labels: Vec<InputZeroLabel>,
        output_zero_labels: Vec<OutputZeroLabel>,
        delta: Block,
    ) -> Self {
        Self {
            input_zero_labels,
            output_zero_labels,
            delta,
        }
    }

    pub fn encode(&self, inputs: &Vec<CircuitInput>) -> Vec<InputValueLabel> {
        assert_eq!(inputs.len(), self.input_zero_labels.len());

        self.input_zero_labels
            .iter()
            .zip(inputs.iter())
            .map(|(x, y)| {
                if y.value.lsb() ^ (x.id == y.id) {
                    InputValueLabel {
                        id: x.id,
                        label: x.zero_label,
                    }
                } else if x.id == y.id {
                    InputValueLabel {
                        id: x.id,
                        label: x.zero_label ^ self.delta,
                    }
                }
                else {
                    panic!("Id not consistent!");
                }
            })
            .collect()
    }

    pub fn decode_info(&self) -> Vec<OutputDecodeInfo> {
        self.output_zero_labels
            .iter()
            .map(|x| OutputDecodeInfo {
                id: x.id,
                decode_info: x.zero_label.lsb(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct GarbledCircuit {
    pub gc_table: GarbledCircuitTable,
    pub gc_local: GarbledCircuitLocal,
}

impl GarbledCircuit {
    pub fn new(gc_table: GarbledCircuitTable, gc_local: GarbledCircuitLocal) -> Self {
        Self { gc_table, gc_local }
    }
}

// /// Complete garbled circuit data, including private data which should not be revealed
// /// to the evaluator
// #[derive(Debug, Clone)]
// pub struct CompleteGarbledCircuit {
//     pub input_labels: Vec<[Block; 2]>,
//     pub wire_labels: Vec<[Block; 2]>,
//     pub table: Vec<[Block; 2]>,
//     pub output_bits: Vec<bool>,
//     pub public_one_label: Block,
//     pub delta: Block,
// }

// /// Garbled circuit data safe to share with evaluator
// #[derive(Debug, Clone)]
// pub struct GarbledCircuit {
//     /// Wire labels corresponding to the generators input bits
//     pub generator_input_labels: Vec<InputLabel>,
//     /// Truth table for garbled AND gates
//     pub table: Vec<[Block; 2]>,
//     /// Wire labels corresponding to public one
//     /// public_one_label = random_label xor delta
//     pub public_one_label: Block,
//     /// LSBs of output labels
//     pub output_bits: Vec<bool>,
// }

// impl CompleteGarbledCircuit {
//     pub fn new(
//         input_labels: Vec<[Block; 2]>,
//         wire_labels: Vec<[Block; 2]>,
//         table: Vec<[Block; 2]>,
//         output_bits: Vec<bool>,
//         public_one_label: Block,
//         delta: Block,
//     ) -> Self {
//         Self {
//             input_labels,
//             wire_labels,
//             table,
//             output_bits,
//             public_one_label,
//             delta,
//         }
//     }

//     /// Converts `CompleteGarbledCircuit` to `GarbledCircuit` which is safe to share with the evaluator
//     pub fn to_public(&self, inputs: &[CircuitInput]) -> GarbledCircuit {
//         let mut generator_input_labels = Vec::with_capacity(inputs.len());
//         for input in inputs.iter() {
//             generator_input_labels.push(InputLabel {
//                 id: input.id,
//                 label: self.input_labels[input.id][input.value.lsb() as usize],
//             });
//         }
//         GarbledCircuit {
//             generator_input_labels,
//             table: self.table.clone(),
//             output_bits: self.output_bits.clone(),
//             public_one_label: self.public_one_label,
//         }
//     }
// }
