use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{AesHash, Block};
use std::time::Duration;

fn bench_cr_hash(c: &mut Criterion) {
    c.bench_function("AesHash::cr_hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<Block>();
        b.iter(|| {
            let z = hash.cr_hash(i, x);
            criterion::black_box(z)
        });
    });
}

fn bench_ccr_hash(c: &mut Criterion) {
    c.bench_function("AesHash::ccr_hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<Block>();
        b.iter(|| {
            let z = hash.ccr_hash(i, x);
            criterion::black_box(z)
        });
    });
}

fn bench_tccr_hash(c: &mut Criterion) {
    c.bench_function("AesHash::tccr_hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<Block>();
        b.iter(|| {
            let z = hash.tccr_hash(i, x);
            criterion::black_box(z)
        });
    });
}

criterion_group! {
    name = aeshash;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_cr_hash, bench_ccr_hash, bench_tccr_hash
}
criterion_main!(aeshash);
