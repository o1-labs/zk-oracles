use circuit::Circuit;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::AesRng;
use crypto_core::Block;
use rand::Rng;
use std::time::Duration;
use twopc::GCGenerator;
use twopc::HalfGateGenerator;
use twopc::InputZeroLabel;

fn bench_garble_adder64(c: &mut Criterion) {
    c.bench_function("garbling adder64", |b| {
        let circ = Circuit::load("../circuit/circuit_files/bristol/adder64.txt").unwrap();
        let mut rng = AesRng::new();

        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        let input_zero_labels: Vec<InputZeroLabel> = (0..circ.ninput_wires)
            .map(|id| InputZeroLabel {
                id,
                zero_label: rng.gen::<Block>(),
            })
            .collect();

        let mut gen = HalfGateGenerator::new(delta);

        b.iter(|| {
            let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();
            criterion::black_box(gc);
        });
    });
}

fn bench_garble_aes_128_reverse(c: &mut Criterion) {
    c.bench_function("garbling aes128 reverse", |b| {
        let circ = Circuit::load("../circuit/circuit_files/bristol/aes_128_reverse.txt").unwrap();
        let mut rng = AesRng::new();

        let mut delta = rng.gen::<Block>();
        delta = delta.set_lsb();

        let input_zero_labels: Vec<InputZeroLabel> = (0..circ.ninput_wires)
            .map(|id| InputZeroLabel {
                id,
                zero_label: rng.gen::<Block>(),
            })
            .collect();

        let mut gen = HalfGateGenerator::new(delta);

        b.iter(|| {
            let gc = gen.garble(&mut rng, &circ, &input_zero_labels).unwrap();
            criterion::black_box(gc);
        });
    });
}
criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_adder64, bench_garble_aes_128_reverse
}
criterion_main!(garbling);
