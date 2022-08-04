//! Define the structure of gates and circuits.
//! Part of the code is derived from TLSNotary. https://github.com/tlsnotary/tlsn

use crate::errors::CircuitEvalError;
use crypto_core::block::Block;

/// `gate_id`: the gate id.
/// `lin_id`, `rin_id` are the wire ids of two fan-in gate inputs.
/// `out_id` is the wire id of the gate output.
#[derive(Clone, Debug, PartialEq)]
pub enum Gate {
    Xor {
        gate_id: usize,
        lin_id: usize,
        rin_id: usize,
        out_id: usize,
    },
    And {
        gate_id: usize,
        lin_id: usize,
        rin_id: usize,
        out_id: usize,
    },
    Inv {
        gate_id: usize,
        lin_id: usize,
        out_id: usize,
    },
}

/// Circuit input
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CircuitInput {
    /// Circuit input id
    pub id: usize,

    /// Circuit input value
    pub value: Block,
}

/// Define a circuit
pub struct Circuit {
    /// Number of gates
    pub ngates: usize,
    /// Number of wires
    pub nwires: usize,
    /// Number of wires for each input
    pub ninput_wires: usize,
    /// Number of output wires
    pub noutput_wires: usize,
    /// All gates in the circuit
    pub gates: Vec<Gate>,
    /// Number of AND gates
    pub nand: usize,
    /// Number of XOR gates
    pub nxor: usize,
    /// Number of INV gates
    pub ninv: usize,
}

impl Circuit {
    pub fn new(ngates: usize, nwires: usize, ninput_wires: usize, noutput_wires: usize) -> Self {
        Circuit {
            ngates,
            nwires,
            ninput_wires,
            noutput_wires,
            gates: Vec::with_capacity(ngates),
            nand: 0,
            nxor: 0,
            ninv: 0,
        }
    }

    /// Evaluate the circuit in plaintext with the provided inputs
    pub fn eval(&self, inputs: Vec<CircuitInput>) -> Result<Vec<Block>, CircuitEvalError> {
        let mut wires: Vec<Option<Block>> = vec![None; self.nwires];
        for input in inputs.iter() {
            wires[input.id] = Some(input.value);
        }

        for gate in self.gates.iter() {
            let (out_id, val) = match *gate {
                Gate::Xor {
                    lin_id,
                    rin_id,
                    out_id,
                    ..
                } => {
                    let x = wires[lin_id].ok_or(CircuitEvalError::UninitializedValue(lin_id))?;
                    let y = wires[rin_id].ok_or(CircuitEvalError::UninitializedValue(rin_id))?;
                    (out_id, x ^ y)
                }
                Gate::And {
                    lin_id,
                    rin_id,
                    out_id,
                    ..
                } => {
                    let x = wires[lin_id].ok_or(CircuitEvalError::UninitializedValue(lin_id))?;
                    let y = wires[rin_id].ok_or(CircuitEvalError::UninitializedValue(rin_id))?;
                    (out_id, x & y)
                }
                Gate::Inv { lin_id, out_id, .. } => {
                    let x = wires[lin_id].ok_or(CircuitEvalError::UninitializedValue(lin_id))?;
                    (out_id, x.flip())
                }
            };
            wires[out_id] = Some(val);
        }

        // The last `noutput_wires` slots store the output bits.
        let outputs = wires[(self.nwires - self.noutput_wires)..]
            .to_vec()
            .iter()
            .map(|w| w.unwrap())
            .collect();
        Ok(outputs)
    }
}
