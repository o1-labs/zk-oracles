use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{AesRng, Block};
use rand::Rng;
use std::time::Duration;

fn bench_clmul(c: &mut Criterion) {
    c.bench_function("Block::clmul", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x.clmul(y);
            criterion::black_box(z)
        });
    });
}

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.gen::<Block>();
            criterion::black_box(block)
        });
    });
}

fn bench_xor(c: &mut Criterion) {
    c.bench_function("Block::xor", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x ^ y;
            criterion::black_box(z)
        });
    });
}

fn bench_u128_xor(c: &mut Criterion) {
    c.bench_function("U128::xor", |b| {
        let x = rand::random::<u128>();
        let y = rand::random::<u128>();
        b.iter(|| {
            let z = x ^ y;
            criterion::black_box(z)
        });
    });
}

fn bench_and(c: &mut Criterion) {
    c.bench_function("Block::and", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x & y;
            criterion::black_box(z)
        });
    });
}

fn bench_u128_and(c: &mut Criterion) {
    c.bench_function("U128::and", |b| {
        let x = rand::random::<u128>();
        let y = rand::random::<u128>();
        b.iter(|| {
            let z = x & y;
            criterion::black_box(z)
        });
    });
}

fn bench_default(c: &mut Criterion) {
    c.bench_function("Block::default", |b| {
        b.iter(|| {
            let z = Block::default();
            criterion::black_box(z)
        })
    });
}

criterion_group! {
    name = block;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_clmul, bench_rand, bench_xor, bench_u128_xor, bench_and, bench_u128_and, bench_default
}
criterion_main!(block);
