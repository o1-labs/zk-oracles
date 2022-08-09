use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes128::new", |b| {
        let key = GenericArray::from([0u8; 16]);
        b.iter(|| {
            let cipher = Aes128::new(&key);
            criterion::black_box(cipher);
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt", |b| {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let cipher = Aes128::new(&key);
        b.iter(|| {
            let c = cipher.encrypt_block(&mut block);
            criterion::black_box(c);
        });
    });
}

fn bench_aes_decrypt(c: &mut Criterion) {
    c.bench_function("Aes128::decrypt", |b| {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let cipher = Aes128::new(&key);
        b.iter(|| {
            let c = cipher.decrypt_block(&mut block);
            criterion::black_box(c);
        });
    });
}

criterion_group! {
    name = aes128;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_new, bench_aes_encrypt, bench_aes_decrypt
}
criterion_main!(aes128);
