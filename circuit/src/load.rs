//! Load Bristol format circuit from files.
//! The code is derived from TLSNotary. https://github.com/tlsnotary/tlsn

use crate::errors::CircuitLoadError;
use crate::gate::{Circuit, Gate};
use anyhow::{anyhow, Context};
use regex::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

/// Parse caputres into a Vec
fn parse_to_vec<'a>(re: &Regex, line: &'a str) -> Result<Vec<&'a str>, CircuitLoadError> {
    let v: Vec<&'a str> = re
        .captures_iter(line)
        .map(|cap| {
            let s = cap.get(1).unwrap().as_str();
            s
        })
        .collect();
    Ok(v)
}

impl Circuit {
    /// Load and Parse circuit files in Bristol Fashion format as specified here:
    /// `https://homes.esat.kuleuven.be/~nsmart/MPC/`
    pub fn load(filename: &str) -> Result<Self, CircuitLoadError> {
        let f = File::open(filename)
            .with_context(|| format!("Failed to read circuit from {}", filename))?;
        let mut reader = BufReader::new(f);

        // Parse first line: ngates nwires\n
        let mut line = String::new();
        let _ = reader.read_line(&mut line).context("Failed to read line")?;
        let re = Regex::new(r"(\d+)").context("Failed to compile regex")?;
        let line_1 = parse_to_vec(&re, &line)?;

        // Check fisrt line has 2 values: ngates, nwires
        if line_1.len() != 2 {
            return Err(CircuitLoadError::ParsingError(anyhow!(
                "Expecting line to be ngates, nwires: {}",
                line
            )));
        }

        let ngates: usize = line_1[0]
            .parse()
            .with_context(|| format!("Failed to parse ngates: {}", line_1[0]))?;
        let nwires: usize = line_1[1]
            .parse()
            .with_context(|| format!("Failed to parse nwires: {}", line_1[1]))?;

        // Parse second line: ninputs input_0_wires input_1_nwires...
        let mut line = String::new();
        let _ = reader.read_line(&mut line).context("Failed to read line")?;
        let re = Regex::new(r"(\d+)\s*").context("Failed to compile regex")?;
        let line_2 = parse_to_vec(&re, &line)?;

        // Number of circuit inputs
        let ninputs: usize = line_2[0]
            .parse()
            .with_context(|| format!("Failed to parse ninputs: {}", line_2[0]))?;
        let input_nwires: Vec<usize> = line_2[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();

        let ninput_wires: usize = input_nwires.iter().sum();

        // Check nwires is specified for every input
        if input_nwires.len() != ninputs {
            return Err(CircuitLoadError::ParsingError(anyhow!(
                "Expecting wire count to be specified for every input: {}",
                line
            )));
        }

        // Parse third line: noutputs output_0_nwires output_1_nwires...
        let mut line = String::new();
        reader.read_line(&mut line).context("Failed to read line")?;
        let re = Regex::new(r"(\d+)\s*").context("Failed to compile regex")?;
        let line_3 = parse_to_vec(&re, &line)?;

        // Number of circuit outputs
        let noutputs: usize = line_3[0]
            .parse()
            .with_context(|| format!("Failed to parse noutputs: {}", line_3[0]))?;
        let output_nwires: Vec<usize> = line_3[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();
        let noutput_wires: usize = output_nwires.iter().sum();

        // Check that nwires is specified for every output
        if output_nwires.len() != noutputs {
            return Err(CircuitLoadError::ParsingError(anyhow!(
                "
            Expecting wire count to be specified for every output: {}",
                line
            )));
        }

        let mut circ = Self::new(ngates, nwires, ninput_wires, noutput_wires);

        let re = Regex::new(r"(\d+|\S+)\s*").context("Failed to compile regex")?;

        let mut gate_id = 0;

        // Process gates
        for line in reader.lines() {
            let line = line.context("Failed to read line")?;
            if line.is_empty() {
                continue;
            }
            let gate_info = parse_to_vec(&re, &line)?;
            let gate_type = gate_info.last().unwrap();
            let gate = match *gate_type {
                "INV" => {
                    let lin_id: usize = gate_info[2].parse().context("Failed to parse gate")?;
                    let out_id: usize = gate_info[3].parse().context("Failed to parse gate")?;
                    circ.ninv += 1;
                    Gate::Inv {
                        gate_id,
                        lin_id,
                        out_id,
                    }
                }
                "AND" => {
                    let lin_id: usize = gate_info[2].parse().context("Failed to parse gate")?;
                    let rin_id: usize = gate_info[3].parse().context("Failed to parse gate")?;
                    let out_id: usize = gate_info[4].parse().context("Failed to parse gate")?;
                    circ.nand += 1;
                    Gate::And {
                        gate_id,
                        lin_id,
                        rin_id,
                        out_id,
                    }
                }
                "XOR" => {
                    let lin_id: usize = gate_info[2].parse().context("Failed to parse gate")?;
                    let rin_id: usize = gate_info[3].parse().context("Failed to parse gate")?;
                    let out_id: usize = gate_info[4].parse().context("Failed to parse gate")?;
                    circ.nxor += 1;
                    Gate::Xor {
                        gate_id,
                        lin_id,
                        rin_id,
                        out_id,
                    }
                }
                _ => {
                    return Err(CircuitLoadError::ParsingError(anyhow!(
                        "Encountered unsupported gate type: {}",
                        gate_type
                    )));
                }
            };
            circ.gates.push(gate);
            gate_id += 1;
        }
        if gate_id != ngates {
            return Err(CircuitLoadError::ParsingError(anyhow!(
                "Expecting {ngates} gates, parsed {gate_id}"
            )));
        }
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::CircuitInput;
    use crypto_core::block::Block;

    #[test]
    fn test_parse_adder64() {
        let circ = Circuit::load("circuit_files/bristol/adder64.txt").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);
        assert_eq!(circ.nxor, 313);
        assert_eq!(circ.nand, 63);
        assert_eq!(circ.ninv, 0);

        // a = 0, b = 0
        let a = vec![Block::from(0u128); 64];
        let b = vec![Block::from(0u128); 64];

        let inputs = [a, b].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        let output = circ.eval(inputs).unwrap();
        assert_eq!(output, vec![Block::from(0u128); 64]);

        // a = 1, b = 0
        let mut a = vec![Block::from(0u128); 64];
        a[0] = Block::from(1u128);

        let b = vec![Block::from(0u128); 64];

        let inputs = [a, b].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        let output = circ.eval(inputs).unwrap();

        let mut res = vec![Block::from(0u128); 64];
        res[0] = Block::from(1u128);

        assert_eq!(output, res);

        // a = 0, b = 1
        let a = vec![Block::from(0u128); 64];
        let mut b = vec![Block::from(0u128); 64];
        b[0] = Block::from(1u128);

        let inputs = [a, b].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        let output = circ.eval(inputs).unwrap();

        let mut res = vec![Block::from(0u128); 64];
        res[0] = Block::from(1u128);

        assert_eq!(output, res);

        // a = 1, b = 1
        let mut a = vec![Block::from(0u128); 64];
        a[0] = Block::from(1u128);
        let mut b = vec![Block::from(0u128); 64];
        b[0] = Block::from(1u128);

        let inputs = [a, b].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        let output = circ.eval(inputs).unwrap();

        let mut res = vec![Block::from(0u128); 64];
        res[1] = Block::from(1u128);

        assert_eq!(output, res);

        // a = 2^64 - 1, b = 1
        let a = vec![Block::from(1u128); 64];
        let mut b = vec![Block::from(0u128); 64];
        b[0] = Block::from(1u128);

        let inputs = [a, b].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        let output = circ.eval(inputs).unwrap();

        let res = vec![Block::from(0u128); 64];

        assert_eq!(output, res);
    }

    #[test]
    fn test_aes() {
        let circ = Circuit::load("circuit_files/bristol/aes_128.txt").unwrap();

        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);
        assert_eq!(circ.nxor, 25124);
        assert_eq!(circ.nand, 6800);
        assert_eq!(circ.ninv, 1692);

        // key = 0^128, pt = 0^128
        let mut key = vec![Block::from(0u128); 128];
        let mut pt = vec![Block::from(0u128); 128];

        let inputs = [key, pt].concat();

        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        // key = 0^128, pt = 1^128
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(1u128); 128];

        let inputs = [key, pt].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        // key = 0^128, pt = 000000010^120
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(0u128); 128];
        pt[7] = Block::from(1u128);
        let inputs = [key, pt].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        // key = 0^128, pt = 0^120(11111111)
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(0u128); 128];
        for i in 0..8 {
            pt[127 - i] = Block::from(1u128);
        }
        let inputs = [key, pt].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");
    }

    #[test]
    fn test_aes_reservse() {
        let circ = Circuit::load("circuit_files/bristol/aes_128_reverse.txt").unwrap();
        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);
        assert_eq!(circ.nxor, 28176);
        assert_eq!(circ.nand, 6400);
        assert_eq!(circ.ninv, 2087);

        // key = 0^128, pt = 0^128
        let mut key = vec![Block::from(0u128); 128];
        let mut pt = vec![Block::from(0u128); 128];

        let inputs = [key, pt].concat();

        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        // key = 0^128, pt = 1^128
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(1u128); 128];

        let inputs = [pt, key].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
           "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        // key = 0^128, pt = 000000010^120
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(0u128); 128];
        pt[7] = Block::from(1u128);
        pt.reverse();
        let inputs = [pt, key].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        // key = 0^128, pt = 0^120(11111111)
        key = vec![Block::from(0u128); 128];
        pt = vec![Block::from(0u128); 128];
        for i in 0..8 {
            pt[127 - i] = Block::from(1u128);
        }
        pt.reverse();
        let inputs = [pt, key].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();

        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i.lsb() as u8).to_string()).collect::<String>(),
            "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");
    }
}
