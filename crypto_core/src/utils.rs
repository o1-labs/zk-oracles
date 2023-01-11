//! Useful utility functions.

use rand::{CryptoRng, Rng};

use crate::Block;

/// Pack a bit slice into bytes.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let nbytes = (bits.len() as f64 / 8.0).ceil() as usize;
    let mut bytes = vec![0; nbytes];
    for i in 0..nbytes {
        for j in 0..8 {
            if 8 * i + j >= bits.len() {
                break;
            }
            bytes[i] |= (bits[8 * i + j] as u8) << j;
        }
    }
    bytes
}

/// Unpack a bit vector from a slice of bytes.
pub fn unpack_bits(bytes: &[u8], size: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(size);
    for (i, byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            if 8 * i + j >= size {
                break;
            }
            bits.push(((byte >> j) & 1) != 0);
        }
    }
    bits
}

/// XOR two byte arrays, outputting the result.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

/// XOR two byte arrays up to `n` bytes, outputting the result.
pub fn xor_n(a: &[u8], b: &[u8], n: usize) -> Vec<u8> {
    a[0..n]
        .iter()
        .zip(b[0..n].iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// XOR two byte arrays in place.
pub fn xor_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

/// XOR two byte arrays up to `n` bytes in place.
pub fn xor_inplace_n(a: &mut [u8], b: &[u8], n: usize) {
    for (a, b) in a[0..n].iter_mut().zip(b.iter()) {
        *a ^= *b;
    }
}

/// AND two byte arrays, outputting the result.
pub fn and(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a & b).collect()
}

/// AND two byte arrays in place.
pub fn and_inplace(a: &mut [u8], b: &[u8]) {
    for (a, b) in a.iter_mut().zip(b.iter()) {
        *a &= *b;
    }
}


/// Fast matrix transpose
#[inline]
pub fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    let mut m_ = vec![0u8; nrows * ncols / 8];
    _transpose(
        m_.as_mut_ptr() as *mut u8,
        m.as_ptr(),
        nrows as u64,
        ncols as u64,
    );
    m_
}

#[inline(always)]
fn _transpose(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64) {
    assert!(nrows >= 16);
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    unsafe { sse_trans(out, inp, nrows, ncols) }
}

#[link(name = "transpose")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

#[inline]
pub fn random_blocks<R: CryptoRng + Rng>(rng: &mut R, num: usize) -> Vec<Block> {
    let mut dest = vec![0u8; num * 16];

    rng.fill_bytes(&mut dest);
    let res: Vec<Block> = dest
        .chunks(16)
        .map(|x| Block::try_from_slice(x).unwrap())
        .collect();
    res
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v__ = xor(&v, &v_);
        let v___ = xor(&v__, &v_);
        assert_eq!(v___, v);
    }

    #[test]
    fn test_xor_inplace() {
        let mut v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let goal = v.clone();
        let v_ = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        xor_inplace(&mut v, &v_);
        xor_inplace(&mut v, &v_);
        assert_eq!(v, goal);
    }

    #[test]
    fn test_and() {
        let v = (0..128).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        let v_ = (0..128).map(|_| 0xFF).collect::<Vec<u8>>();
        let v__ = and(&v, &v_);
        assert_eq!(v__, v);
    }

    fn _transpose(nrows: usize, ncols: usize) {
        let m = (0..nrows * ncols / 8)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        let m_ = m.clone();
        let m = transpose(&m, nrows, ncols);
        let m = transpose(&m, ncols, nrows);
        assert_eq!(m, m_);
    }

    #[test]
    fn test_transpose() {
        _transpose(16, 16);
        _transpose(24, 16);
        _transpose(32, 16);
        _transpose(40, 16);
        _transpose(128, 16);
        _transpose(128, 24);
        _transpose(128, 128);
        _transpose(128, 1 << 16);
        _transpose(128, 1 << 18);
        _transpose(32, 32);
        _transpose(64, 32);
    }

    #[test]
    fn test_bit_packing() {
        let m = 256;
        let mut v = vec![0u8; m / 8];
        for x in v.iter_mut() {
            *x = rand::random();
        }

        let bits = unpack_bits(&v, m);
        let res = pack_bits(&bits);
        assert_eq!(res, v);

        let mut bits = vec![false; m];
        for x in bits.iter_mut() {
            *x = rand::random();
        }

        let bytes = pack_bits(&bits);
        let res = unpack_bits(&bytes, m);
        assert_eq!(res, bits);
    }
}
