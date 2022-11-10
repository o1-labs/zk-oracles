pub mod notary_file;

pub use notary_file::*;

use mina_hasher::{DomainParameter, Fp, Hashable, Hasher, PoseidonHasherKimchi, ROInput};

/// Version of ZkOracles
#[derive(Debug, Clone)]
pub enum ZkOraclesVersion {
    VERSION0_1_0 = 0x00,
}

impl DomainParameter for ZkOraclesVersion {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

/// Input struct of Poseidon-based commitment.
#[derive(Clone)]
pub struct PInput {
    str: [u8; 16],
    element: Fp,
}

impl Hashable for PInput {
    type D = u64;

    fn to_roinput(&self) -> ROInput {
        ROInput::new()
            .append_bytes(&self.str)
            .append_field(self.element)
    }

    fn domain_string(_: Self::D) -> Option<String> {
        None
    }
}

type PHasher = PoseidonHasherKimchi<PInput>;

/// Generate Poseidon-based commitment for 128-bit key shares
pub fn poseidon_commitment(hasher: &mut PHasher, input: [u8; 16], randomness: Fp) -> Fp {
    let pinput = PInput {
        str: input,
        element: randomness,
    };

    hasher.update(&pinput);
    hasher.digest()
}

/// Verify Poseidon-based commitment for 128-bit key shares
pub fn poseidon_open(hasher: &mut PHasher, input: [u8; 16], randomness: Fp, com: Fp) -> bool {
    let pinput = PInput {
        str: input,
        element: randomness,
    };

    hasher.update(&pinput);
    let res = hasher.digest();
    if res == com {
        true
    } else {
        false
    }
}

mod tests {
    #[test]
    fn poseidon_com_test() {
        use crate::poseidon_open;
        use crate::{poseidon_commitment, PInput};
        use mina_hasher::create_kimchi;
        use mina_hasher::Fp;

        let input = [1u8; 16];
        let randomness = Fp::from(10);

        let mut hasher = create_kimchi::<PInput>(0);
        let com = poseidon_commitment(&mut hasher, input, randomness);

        let res = poseidon_open(&mut hasher, input, randomness, com);
        assert_eq!(res, true);
    }
}
