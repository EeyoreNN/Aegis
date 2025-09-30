// Cryptography benchmarks for Aegis
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use aegis::crypto::{
    kyber::{KeyPair, PublicKey},
    symmetric::{SymmetricKey, encrypt_simple, decrypt_simple},
    kdf::{derive_master_key, derive_message_key, blake3_keyed_hash},
    ratchet::RatchetState,
    random::generate_key,
};

fn bench_kyber_keygen(c: &mut Criterion) {
    c.bench_function("kyber1024_keypair_generation", |b| {
        b.iter(|| {
            black_box(KeyPair::generate().unwrap())
        })
    });
}

fn bench_kyber_encapsulation(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let public_key = keypair.public_key().clone();

    c.bench_function("kyber1024_encapsulation", |b| {
        b.iter(|| {
            black_box(public_key.encapsulate().unwrap())
        })
    });
}

fn bench_kyber_decapsulation(c: &mut Criterion) {
    let keypair = KeyPair::generate().unwrap();
    let (_, ciphertext) = keypair.public_key().encapsulate().unwrap();

    c.bench_function("kyber1024_decapsulation", |b| {
        b.iter(|| {
            black_box(keypair.decapsulate(&ciphertext).unwrap())
        })
    });
}

fn bench_chacha20_encryption(c: &mut Criterion) {
    let key_bytes = generate_key().unwrap();
    let key = SymmetricKey::new(key_bytes);

    let mut group = c.benchmark_group("chacha20poly1305_encryption");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(encrypt_simple(&key, &plaintext).unwrap())
            })
        });
    }
    group.finish();
}

fn bench_chacha20_decryption(c: &mut Criterion) {
    let key_bytes = generate_key().unwrap();
    let key = SymmetricKey::new(key_bytes);

    let mut group = c.benchmark_group("chacha20poly1305_decryption");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        let encrypted = encrypt_simple(&key, &plaintext).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(decrypt_simple(&key, &encrypted).unwrap())
            })
        });
    }
    group.finish();
}

fn bench_hkdf_derivation(c: &mut Criterion) {
    let shared_secret = [42u8; 32];
    let salt = b"test-salt";

    c.bench_function("hkdf_master_key_derivation", |b| {
        b.iter(|| {
            black_box(derive_master_key(&shared_secret, salt).unwrap())
        })
    });
}

fn bench_ratchet_send_key(c: &mut Criterion) {
    let root_key = [1u8; 32];
    let mut ratchet = RatchetState::new(root_key);

    c.bench_function("ratchet_next_send_key", |b| {
        b.iter(|| {
            black_box(ratchet.next_send_key().unwrap())
        })
    });
}

fn bench_ratchet_recv_key(c: &mut Criterion) {
    let root_key = [2u8; 32];
    let mut ratchet = RatchetState::new(root_key);

    c.bench_function("ratchet_get_recv_key", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let result = black_box(ratchet.get_recv_key(counter).unwrap());
            counter += 1;
            result
        })
    });
}

fn bench_blake3_hash(c: &mut Criterion) {
    let key = [3u8; 32];

    let mut group = c.benchmark_group("blake3_keyed_hash");

    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(blake3_keyed_hash(&key, &data))
            })
        });
    }
    group.finish();
}

fn bench_message_key_derivation(c: &mut Criterion) {
    let chain_key = [4u8; 32];

    c.bench_function("derive_message_key", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let result = black_box(derive_message_key(&chain_key, counter).unwrap());
            counter += 1;
            result
        })
    });
}

fn bench_full_encryption_flow(c: &mut Criterion) {
    c.bench_function("full_message_encryption_flow", |b| {
        let root_key = [5u8; 32];
        let mut ratchet = RatchetState::new(root_key);
        let plaintext = b"Hello, this is a test message!";

        b.iter(|| {
            let (key, _counter) = ratchet.next_send_key().unwrap();
            let encrypted = encrypt_simple(&key, plaintext).unwrap();
            black_box(encrypted)
        })
    });
}

fn bench_full_decryption_flow(c: &mut Criterion) {
    c.bench_function("full_message_decryption_flow", |b| {
        let root_key = [6u8; 32];
        let mut ratchet = RatchetState::new(root_key);
        let plaintext = b"Hello, this is a test message!";

        // Pre-encrypt messages
        let mut encrypted_messages = Vec::new();
        for i in 0..100 {
            let (key, _) = ratchet.next_send_key().unwrap();
            encrypted_messages.push(encrypt_simple(&key, plaintext).unwrap());
        }

        // Reset ratchet for decryption
        let mut decrypt_ratchet = RatchetState::new(root_key);
        let mut counter = 0;

        b.iter(|| {
            let (key, _) = decrypt_ratchet.next_send_key().unwrap();
            let decrypted = decrypt_simple(&key, &encrypted_messages[counter % 100]).unwrap();
            counter += 1;
            black_box(decrypted)
        })
    });
}

criterion_group!(
    crypto_benches,
    bench_kyber_keygen,
    bench_kyber_encapsulation,
    bench_kyber_decapsulation,
    bench_chacha20_encryption,
    bench_chacha20_decryption,
    bench_hkdf_derivation,
    bench_ratchet_send_key,
    bench_ratchet_recv_key,
    bench_blake3_hash,
    bench_message_key_derivation,
    bench_full_encryption_flow,
    bench_full_decryption_flow
);

criterion_main!(crypto_benches);
