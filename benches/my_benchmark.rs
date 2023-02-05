use criterion::{criterion_group, criterion_main, Criterion};

use ark_std::{UniformRand, ops::Mul};

use ark_bls12_381::{Bls12_381, G1Projective as G, G1Affine as GAffine, G2Projective as G2, Fr as ScalarField, Fq as F};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};


use ntat::client::*;
use ntat::util::*;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let sk_c = ScalarField::rand(&mut rng);
    let pk_c = pp.g1.mul(sk_c);

    // Server KeyGen
    let sk_s = ScalarField::rand(&mut rng);
    let pk_s = pp.g2.mul(sk_s);

    let rand_state = ScalarField::rand(&mut rng);
    let mut client = Client::new(&pp, pk_s, rand_state);

    c.bench_function("Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, sk_c, pk_s)));

    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);

    c.bench_function("Server Issue", |b| b.iter(|| server_issue(&mut rng, &pp, sk_s, pk_c, &query)));
    let response = server_issue(&mut rng, &pp, sk_s, pk_c, &query);

    let r = response.unwrap();
    c.bench_function("Client Final", |b| b.iter(|| client.client_final(&r)));
    let token = client.client_final(&r);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);