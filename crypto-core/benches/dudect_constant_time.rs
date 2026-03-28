// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
//! dudect constant-time verification harnesses for Continuum Ghost.
//!
//! Welch's t-test on timing measurements detects whether crypto operations
//! leak timing information based on their inputs.
//!
//! |t| < 4.5 after 10k+ samples = NO detectable leak (PASS).
//! |t| > 4.5 = timing leak detected (FAIL).
//!
//! Reference: Reparaz, Balasch, Verbauwhede. "dude, is my code constant time?"

#[macro_use]
extern crate dudect_bencher;
use dudect_bencher::{BenchRng, Class, CtRunner};
use curve25519_dalek::scalar::Scalar;
use twofapi_crypto_core::{commit, generators, is_identity, oprf, pedersen};

const SAMPLES: usize = 10_000;

fn rand_scalar() -> Scalar {
    let mut buf = [0u8; 64];
    getrandom::getrandom(&mut buf).unwrap();
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn rand_class() -> Class {
    let mut b = [0u8; 1];
    getrandom::getrandom(&mut b).unwrap();
    if b[0] & 1 == 0 { Class::Left } else { Class::Right }
}

// ======================================================
// Harness 1: Sigma proof equation verification
// valid proof (Left) vs invalid proof (Right)
// ======================================================
fn dudect_verify_equation(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let (g, h) = generators::generators();
    let g_bytes = g.compress().to_bytes();
    let h_bytes = h.compress().to_bytes();

    let s = rand_scalar();
    let r = rand_scalar();
    let c_bytes = commit(&s, &r).compress().to_bytes();

    let ks = rand_scalar();
    let kr = rand_scalar();
    let a_bytes = commit(&ks, &kr).compress().to_bytes();

    let challenge = rand_scalar();
    let ch_bytes = challenge.to_bytes();

    let valid_zs = (ks + challenge * s).to_bytes();
    let valid_zr = (kr + challenge * r).to_bytes();
    let mut invalid_zs = [0u8; 32];
    let mut invalid_zr = [0u8; 32];
    getrandom::getrandom(&mut invalid_zs).unwrap();
    getrandom::getrandom(&mut invalid_zr).unwrap();

    for _ in 0..SAMPLES {
        let class = rand_class();
        let (zs, zr) = match class {
            Class::Left => (valid_zs, valid_zr),
            Class::Right => (invalid_zs, invalid_zr),
        };
        runner.run_one(class, || {
            twofapi_crypto_core::verify_equation_raw(
                &g_bytes, &h_bytes, &c_bytes, &a_bytes,
                &ch_bytes, &zs, &zr,
            )
        });
    }
}

// ======================================================
// Harness 2: OPRF evaluate — key=1 (Left) vs random (Right)
// ======================================================
fn dudect_oprf_evaluate(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let mut pw = [0u8; 32];
    getrandom::getrandom(&mut pw).unwrap();
    let blinded = oprf::hash_to_group(&pw);

    let fixed_key = Scalar::ONE;
    let random_key = rand_scalar();

    for _ in 0..SAMPLES {
        let class = rand_class();
        let key = match class {
            Class::Left => fixed_key,
            Class::Right => random_key,
        };
        runner.run_one(class, || {
            oprf::evaluate(&blinded, &key)
        });
    }
}

// ======================================================
// Harness 3: Identity check — identity (Left) vs random (Right)
// ======================================================
fn dudect_identity_check(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let identity = [0u8; 32];
    let random = commit(&rand_scalar(), &rand_scalar()).compress().to_bytes();

    for _ in 0..SAMPLES {
        let class = rand_class();
        let input = match class {
            Class::Left => identity,
            Class::Right => random,
        };
        runner.run_one(class, || {
            is_identity(&input)
        });
    }
}

// ======================================================
// Harness 4: Commitment verify — correct (Left) vs wrong (Right)
// ======================================================
fn dudect_commitment_verify(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let s = rand_scalar();
    let r = rand_scalar();
    let c = commit(&s, &r);
    let wrong_s = rand_scalar();

    for _ in 0..SAMPLES {
        let class = rand_class();
        let (ts, tr) = match class {
            Class::Left => (s, r),
            Class::Right => (wrong_s, r),
        };
        runner.run_one(class, || {
            pedersen::verify_commitment(&c, &ts, &tr)
        });
    }
}

ctbench_main!(
    dudect_verify_equation,
    dudect_oprf_evaluate,
    dudect_identity_check,
    dudect_commitment_verify
);
