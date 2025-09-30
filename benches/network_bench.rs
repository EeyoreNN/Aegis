// Network benchmarks for Aegis
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use aegis::network::protocol::{Message, frame_message, parse_framed_message};

fn bench_message_serialization(c: &mut Criterion) {
    let msg = Message::heartbeat();

    c.bench_function("message_serialization", |b| {
        b.iter(|| {
            black_box(msg.to_bytes().unwrap())
        })
    });
}

fn bench_message_deserialization(c: &mut Criterion) {
    let msg = Message::heartbeat();
    let bytes = msg.to_bytes().unwrap();

    c.bench_function("message_deserialization", |b| {
        b.iter(|| {
            black_box(Message::from_bytes(&bytes).unwrap())
        })
    });
}

fn bench_message_framing(c: &mut Criterion) {
    let msg = Message::heartbeat();

    c.bench_function("message_framing", |b| {
        b.iter(|| {
            black_box(frame_message(&msg).unwrap())
        })
    });
}

fn bench_frame_parsing(c: &mut Criterion) {
    let msg = Message::heartbeat();
    let framed = frame_message(&msg).unwrap();

    c.bench_function("frame_parsing", |b| {
        b.iter(|| {
            black_box(parse_framed_message(&framed).unwrap())
        })
    });
}

fn bench_encrypted_message_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypted_message_serialization");

    for size in [64, 256, 1024, 4096].iter() {
        let nonce = [0u8; 24];
        let ciphertext = vec![0u8; *size];
        let msg = Message::encrypted(nonce, ciphertext, 0, 0);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(msg.to_bytes().unwrap())
            })
        });
    }
    group.finish();
}

fn bench_message_validation(c: &mut Criterion) {
    let msg = Message::heartbeat();

    c.bench_function("message_validation", |b| {
        b.iter(|| {
            black_box(msg.validate().unwrap())
        })
    });
}

fn bench_full_message_roundtrip(c: &mut Criterion) {
    c.bench_function("full_message_roundtrip", |b| {
        let msg = Message::heartbeat();

        b.iter(|| {
            let framed = frame_message(&msg).unwrap();
            let (parsed, _) = parse_framed_message(&framed).unwrap();
            black_box(parsed)
        })
    });
}

criterion_group!(
    network_benches,
    bench_message_serialization,
    bench_message_deserialization,
    bench_message_framing,
    bench_frame_parsing,
    bench_encrypted_message_serialization,
    bench_message_validation,
    bench_full_message_roundtrip
);

criterion_main!(network_benches);
