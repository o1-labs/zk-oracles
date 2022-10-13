use rand::SeedableRng;

use crate::{AesRng, Block};
pub struct Prg;

impl Prg {
    pub fn gen_from_seed(seed: Block, num: usize) -> Vec<Block> {
        let mut rng = AesRng::from_seed(seed);
        rng.gen_blocks(num)
    }
}

#[test]
fn prg_test() {
    let num = 10;
    let mut rng = AesRng::new();

    let seed = rng.gen_block();
    let res1 = Prg::gen_from_seed(seed, num);
    let res2 = Prg::gen_from_seed(seed, num);

    let _ = res1
        .iter()
        .zip(res2.iter())
        .map(|(x, y)| assert_eq!(*x, *y));
}
