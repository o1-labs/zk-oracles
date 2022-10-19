//! Implement the KOS15 OT Extension protocol.

use crate::{OtReceiver, OtSender};
use crypto_core::Block;
pub struct KOSSender<OT: OtReceiver<Msg = Block>> {
    pub ot: OT,
}



pub struct KOSReceiver<OT: OtSender<Msg = Block>> {
    pub ot: OT,
}
