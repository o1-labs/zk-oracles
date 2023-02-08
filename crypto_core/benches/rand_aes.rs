use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::AesRng;
use rand_core::RngCore;
use std::time::Duration;

fn bench_aes_rand(c: &mut Criterion) {
    c.bench_function("AesRng::rand", |b| {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(&mut x));
    });
}

fn bench_rand_block(c: &mut Criterion) {
    c.bench_function("random_blocks", |b| {
        let mut rng = AesRng::new();
        b.iter(|| rng.random_blocks(16 * 1024));
    });
}

criterion_group! {
    name = aesrng;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_rand,bench_rand_block
}
criterion_main!(aesrng);
