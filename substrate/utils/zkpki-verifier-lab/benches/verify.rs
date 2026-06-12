//! Stage 3 criterion benchmark — measures pure `verify_proof` latency.
//!
//! The one number we care about: **how many milliseconds does it take
//! to verify one mime_wrap proof on reference hardware?**
//!
//! That number multiplied by the Substrate weight-per-ms conversion
//! (typically ~1_000_000 WU / ms for the Rostro node) gives us the weight
//! cost of a single sign extrinsic. If it fits in a reasonable
//! fraction of a block's weight budget, we ship. If not, we either
//! optimise (swap to BLS12-381 with host-function pairing, batch
//! verification) or rethink.
//!
//! Setup (zkey parse + proof generation) is outside the measurement
//! — the benchmark loop only times `verify_proof`. Pvk is prepared
//! once and reused; the pallet caches the prepared form in runtime
//! storage, so per-verify cost is what matters.

use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use zkpki_verifier_lab::{generate_sample_proof, prepare_vk, verify_proof};

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("fixtures");
    p.push(name);
    p
}

fn bench_verify(c: &mut Criterion) {
    // One-shot setup outside the measurement loop.
    let sample = generate_sample_proof(
        fixture("mime_wrap.wasm"),
        fixture("mime_wrap.r1cs"),
        fixture("mime_wrap_final.zkey"),
    )
    .expect("sample proof generation failed (check fixtures/ symlinks)");
    let pvk = prepare_vk(&sample.vk);

    let mut group = c.benchmark_group("mime_wrap");
    // Verification is fast (<100ms expected); keep sample count modest.
    group.sample_size(50);
    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            let ok = verify_proof(&sample.proof_bytes, &sample.public_inputs, &pvk)
                .expect("verify errored on well-formed proof");
            assert!(ok);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
