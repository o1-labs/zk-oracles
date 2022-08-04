use circuit::gate::{Circuit, CircuitInput};
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::block::Block;
use std::time::Duration;

fn bench_aes_128_circuit_eval(c: &mut Criterion) {
    c.bench_function("Aes_128_circuit_eval", |b| {
        let key = vec![Block::from(0u128); 128];
        let pt = vec![Block::from(0u128); 128];
        let inputs = [key, pt].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let circ = Circuit::load("circuit_files/bristol/aes_128.txt").unwrap();
        b.iter(|| {
            let res = circ.eval(inputs.clone()).unwrap();
            criterion::black_box(res);
        });
    });
}

fn bench_aes_128_reverse_circuit_eval(c: &mut Criterion) {
    c.bench_function("Aes_128_reverse_circuit_eval", |b| {
        let key = vec![Block::from(0u128); 128];
        let pt = vec![Block::from(0u128); 128];
        let inputs = [key, pt].concat();
        let inputs: Vec<CircuitInput> = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let circ = Circuit::load("circuit_files/bristol/aes_128_reverse.txt").unwrap();
        b.iter(|| {
            let res = circ.eval(inputs.clone()).unwrap();
            criterion::black_box(res);
        });
    });
}

criterion_group! {
    name = aes128_eval;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_128_circuit_eval, bench_aes_128_reverse_circuit_eval
}
criterion_main!(aes128_eval);
