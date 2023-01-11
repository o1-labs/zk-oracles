//! Implement Hash-Based Commitment
use sha2::{Digest, Sha256};

/// The struct of Commitment.
pub struct Commitment;

impl Commitment {
    /// Commit messages.
    pub fn commit(input: &[u8], r: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.update(r.as_ref());

        let mut res = [0u8; 32];
        res.copy_from_slice(&hasher.finalize());

        res
    }

    /// Open and check commitment.
    pub fn check(input: &[u8], r: &[u8], com: &[u8; 32]) -> bool {
        let res = Self::commit(input, r);

        res == *com
    }
}

#[cfg(test)]
mod tests {
    use super::Commitment;

    #[test]
    fn test_com() {
        let input = [2u8; 64];
        let r = [1u8; 16];

        let com = Commitment::commit(&input, &r);
        assert!(Commitment::check(&input, &r, &com));
    }
}
