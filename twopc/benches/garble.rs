use circuit::Circuit;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::AesRng;
use std::time::Duration;
use twopc::GCGenerator;
use twopc::HalfGateGenerator;

fn bench_garble_adder64(c: &mut Criterion) {
    c.bench_function("garbling adder64", |b| {
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();
        let mut rng = AesRng::new();
        let gen = HalfGateGenerator;

        b.iter(|| {
            let complete_gc = gen.garble(&mut rng, &circ).unwrap();
            criterion::black_box(complete_gc);
        });
    });
}

fn bench_garble_aes_128_reverse(c: &mut Criterion) {
    c.bench_function("garbling aes128 reverse", |b| {
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128_reverse.txt").unwrap();
        let mut rng = AesRng::new();
        let gen = HalfGateGenerator;

        b.iter(|| {
            let complete_gc = gen.garble(&mut rng, &circ).unwrap();
            criterion::black_box(complete_gc);
        });
    });
}
criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_adder64, bench_garble_aes_128_reverse
}
criterion_main!(garbling);
