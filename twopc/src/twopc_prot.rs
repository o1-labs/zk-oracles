use circuit::Circuit;
use crypto_core::{AbstractChannel, Block};
use rand::{CryptoRng, Rng};

use crate::{
    COReceiver, CotSender, GCGenerator, HalfGateEvaluator, HalfGateGenerator,
    KOSSender, WireLabel, send_gc,
};

use std::io::Result;

pub enum Party {
    ALICE,
    BOB,
}

#[derive(Clone)]
pub enum GCParty {
    GEN(HalfGateGenerator),
    EVA(HalfGateEvaluator),
}

pub struct TwopcProtocol<C: AbstractChannel> {
    pub channel: C,
    pub party: Party,
    pub delta: Block,
    pub gc_party: GCParty,
}

impl<C: AbstractChannel> TwopcProtocol<C> {
    pub fn new<R: Rng + CryptoRng>(channel: C, party: Party, rng: &mut R) -> Self {
        match party {
            Party::ALICE => {
                let delta = rng.gen::<Block>();
                let gen = HalfGateGenerator::new(delta);
                let gc_party = GCParty::GEN(gen);
                Self {
                    channel,
                    party,
                    delta,
                    gc_party,
                }
            }
            Party::BOB => {
                let delta = Block::default();
                let eva = HalfGateEvaluator::new();
                let gc_party = GCParty::EVA(eva);
                Self {
                    channel,
                    party,
                    delta,
                    gc_party,
                }
            }
        }
    }

    pub fn compute<R: Rng + CryptoRng>(
        &mut self,
        party: Party,
        rng: &mut R,
        circ: &Circuit,
        input_alice: &[bool],
        input_bob: &[bool],
    ) -> Result<()> {
        match party {
            Party::ALICE => {
                let bob_len = input_bob.len();
                let mut kosot = KOSSender::new(COReceiver);
                kosot
                    .send_init_with_delta(&mut self.channel, rng, self.delta)
                    .unwrap();

                let bob_input_blks = kosot.send(&mut self.channel, rng, bob_len).unwrap();
                let bob_input_zero_blks = bob_input_blks
                    .into_iter()
                    .map(|(x, _)| x)
                    .collect::<Vec<Block>>();

                let alice_input_zero_blks = (0..input_alice.len())
                    .into_iter()
                    .map(|_| rng.gen::<Block>())
                    .collect::<Vec<Block>>();

                let input_zero_blks = [alice_input_zero_blks, bob_input_zero_blks].concat();

                let input_zero_labels = (0..circ.ninput_wires)
                    .zip(input_zero_blks)
                    .map(|(id, label)| WireLabel { id, label })
                    .collect::<Vec<WireLabel>>();

                let gc_party = self.gc_party.clone();
                match gc_party {
                    GCParty::GEN(mut gen) => {
                        //encode(labels, inputs, delta)

                        let gc = gen.garble(rng, circ, &input_zero_labels).unwrap();
                        send_gc(&mut self.channel, &gc).unwrap();
                    }
                    _ => {}
                }
            }
            Party::BOB => {}
        }

        Ok(())
    }

    pub fn finalize() {}

    pub fn composite<R: Rng + CryptoRng>(
        party: Party,
        rng: &mut R,
        circ: &Circuit,
        input: &[bool],
    ) {
        match party {
            Party::ALICE => {}
            Party::BOB => {}
        }
    }

    pub fn reveal() {}
}


