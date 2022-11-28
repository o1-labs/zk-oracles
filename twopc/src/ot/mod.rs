//！ Provides traits for oblivious transfer (OT) protocols.
//! These traits focus on 1-out-of-2 OTs.

pub mod co;
pub mod errors;

pub use co::*;
pub use errors::{OTReceiverError, OTSenderError};

use crypto_core::AbstractChannel;
use rand::{CryptoRng, Rng};

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
