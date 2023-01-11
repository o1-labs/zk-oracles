//! Implementations of correlation-robust hash functions (and their variants)
//! based on fixed-key AES.

use crate::block::Block;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use core::arch::x86_64::*;
use once_cell::sync::Lazy;

pub struct AesHash {
    aes: Aes128,
}

pub static AES_HASH: Lazy<AesHash> = Lazy::new(|| {
    let key = GenericArray::from([0u8; 16]);
    let aes = Aes128::new(&key);
    AesHash { aes }
});

impl AesHash {
    /// Initialize the hash function using `key`.
    #[inline]
    pub fn new(key: Block) -> Self {
        let key_byte: [u8; 16] = key.into();
        let key = GenericArray::from(key_byte);
        let aes = Aes128::new(&key);
        AesHash { aes }
    }

    /// Correlation-robust hash function for 128-bit inputs (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.2).
    ///
    /// The function computes `π(x) ⊕ x`.
    #[inline]
    pub fn cr_hash(&self, _i: Block, x: Block) -> Block {
        let y: [u8; 16] = x.into();
        let mut y = GenericArray::from(y);
        self.aes.encrypt_block(&mut y);
        let y = Block::try_from_slice(y.as_slice()).unwrap();
        y ^ x
    }

    /// Circular correlation-robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.3).
    ///
    /// The function computes `H(σ(x))`, where `H` is a correlation-robust hash
    /// function and `σ(x₀ || x₁) = (x₀ ⊕ x₁) || x₁`.
    #[inline]
    pub fn ccr_hash(&self, i: Block, x: Block) -> Block {
        unsafe {
            let x = _mm_xor_si128(
                _mm_shuffle_epi32(x.into(), 78),
                #[allow(overflowing_literals)]
                _mm_and_si128(x.into(), _mm_set_epi64x(0xFFFF_FFFF_FFFF_FFFF, 0x00)),
            );
            self.cr_hash(i, Block::from(x))
        }
    }

    /// Tweakable circular correlation robust hash function (cf.
    /// <https://eprint.iacr.org/2019/074>, §7.4).
    ///
    /// The function computes `π(π(x) ⊕ i) ⊕ π(x)`.
    #[inline]
    pub fn tccr_hash(&self, i: Block, x: Block) -> Block {
        let y: [u8; 16] = x.into();
        let mut y = GenericArray::from(y);
        self.aes.encrypt_block(&mut y);
        let y = Block::try_from_slice(y.as_slice()).unwrap();

        let t = y ^ i;

        let t: [u8; 16] = t.into();
        let mut z = GenericArray::from(t);
        self.aes.encrypt_block(&mut z);
        let z = Block::try_from_slice(z.as_slice()).unwrap();
        y ^ z
    }
}
