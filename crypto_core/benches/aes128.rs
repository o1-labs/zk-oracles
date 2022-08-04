use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128 as Native_Aes128;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{Aes128, Block};
use std::time::Duration;

fn bench_native_aes_new(c: &mut Criterion) {
    c.bench_function("Native_Aes128::new", |b| {
        let key = GenericArray::from([0u8; 16]);
        b.iter(|| {
            let cipher = Native_Aes128::new(&key);
            criterion::black_box(cipher);
        });
    });
}

fn bench_native_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Native_Aes128::encrypt", |b| {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let cipher = Native_Aes128::new(&key);
        b.iter(|| {
            let c = cipher.encrypt_block(&mut block);
            criterion::black_box(c);
        });
    });
}

fn bench_native_aes_decrypt(c: &mut Criterion) {
    c.bench_function("Native_Aes128::decrypt", |b| {
        let key = GenericArray::from([0u8; 16]);
        let mut block = GenericArray::from([42u8; 16]);
        let cipher = Native_Aes128::new(&key);
        b.iter(|| {
            let c = cipher.decrypt_block(&mut block);
            criterion::black_box(c);
        });
    });
}

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes128::new", |b| {
        let key = rand::random::<Block>();
        b.iter(|| {
            let aes = Aes128::new(key);
            criterion::black_box(aes)
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let block = rand::random::<Block>();
        b.iter(|| {
            let c = aes.encrypt(block);
            criterion::black_box(c)
        });
    });
}

fn bench_aes_encrypt4(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt4", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let blocks = rand::random::<[Block; 4]>();
        b.iter(|| {
            let c = aes.encrypt4(blocks);
            criterion::black_box(c)
        });
    });
}

fn bench_aes_encrypt8(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt8", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let blocks = rand::random::<[Block; 8]>();
        b.iter(|| {
            let c = aes.encrypt8(blocks);
            criterion::black_box(c)
        });
    });
}

criterion_group! {
    name = aes128;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_native_aes_new, bench_native_aes_encrypt, bench_native_aes_decrypt, bench_aes_new, bench_aes_encrypt, bench_aes_encrypt4, bench_aes_encrypt8
}
criterion_main!(aes128);
