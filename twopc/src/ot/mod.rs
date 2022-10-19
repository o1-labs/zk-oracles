//！ Provides traits for oblivious transfer (OT) protocols.
//! These traits focus on 1-out-of-2 OTs.

pub mod co;
pub mod errors;
pub mod kos;

pub use co::*;
pub use errors::{OTReceiverError, OTSenderError};
pub use kos::*;

use crypto_core::AbstractChannel;
use crypto_core::Block;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{CryptoRng, Rng};
use sha2::Digest;

/// Sender of OT
pub trait OtSender
where
    Self: Sized,
{
    /// Message type.
    type Msg: Sized + AsMut<[u8]>;

    /// Send messages.
    fn send<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut R,
    ) -> Result<(), OTSenderError>;
}

/// Receiver of OT
pub trait OtReceiver
where
    Self: Sized,
{
    /// Message type.
    type Msg: Sized + AsMut<[u8]>;

    /// Receive messages.
    fn receive<C: AbstractChannel, R: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut R,
    ) -> Result<Vec<Self::Msg>, OTReceiverError>;
}

pub(crate) fn hash_to_block(
    mut hasher: sha2::Sha256,
    r: &RistrettoPoint,
    m: &RistrettoPoint,
) -> Block {
    let r_str = r.compress().to_bytes();
    let m_str = m.compress().to_bytes();
    hasher.update([r_str, m_str].concat());

    let mut res = [0u8; 16];
    res.copy_from_slice(&hasher.finalize()[0..16]);
    Block::from(res)
}
