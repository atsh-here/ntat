use criterion::{criterion_group, criterion_main, Criterion};

// use ark_std::{UniformRand, ops::Mul};

// use ark_bls12_381::{Bls12_381, G1Projective as G, G1Affine as GAffine, G2Projective as G2, Fr as ScalarField, Fq as F};
// use ark_ec::short_weierstrass::Projective;
// use ark_bls12_381::g1::Config as g1config;
// use ark_bls12_381::g2::Config as g2config;
// use rand::rngs::ThreadRng;
// use sha256::digest;
// use ark_ff::fields::{PrimeField, Field};



fn criterion_benchmark(c: &mut Criterion) {
    use ark_std::{UniformRand, ops::Mul};

    use ark_secp256k1::Fr as ScalarField; 
    use ntat::client::*;
    use ntat::server::*;
    use ntat::util::*;

    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let sk_c = ScalarField::rand(&mut rng);
    let pk_c = pp.g1.mul(sk_c);

    // Server KeyGen
    let sk_s = ScalarField::rand(&mut rng);
    let pk_s = pp.g2.mul(sk_s);

    let rand_state = ScalarField::rand(&mut rng);
    let rand_server_state = ScalarField::rand(&mut rng);
    let mut client = Client::new(&pp, pk_s, rand_state);
    let mut server = Server::new(&pp, pk_c, rand_server_state);

    c.bench_function("Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, sk_c, pk_s)));

    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);

    c.bench_function("Server Issue", |b| b.iter(|| server_issue(&mut rng, &pp, sk_s, pk_c, &query)));
    let response = server.server_issue(&mut rng, &pp, sk_s, pk_c, &query);

    let r = response.unwrap();
    c.bench_function("Client Final", |b| b.iter(|| client.client_final(&r)));
    let token = client.client_final(&r);
    let extracted_token = token.unwrap();

    c.bench_function("Client Prove Redemption Part 1", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s)));
    let proof1 = client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s);

    c.bench_function("Server Verify Redemption Part 1", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &extracted_token, sk_s, &proof1)));
    let c_ = server.server_verify_redemption1(&mut rng, &extracted_token, sk_s, &proof1);

    c.bench_function("Client Prove Redemption Part 2", |b| b.iter(|| client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap())));
    let proof2 = client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap());

    c.bench_function("Server Verify Redemption Part 2", |b| b.iter(|| server.server_verify_redemption2(&extracted_token, sk_s, &proof2)));
    let verified = server.server_verify_redemption2(&extracted_token, sk_s, &proof2);

    //assert_eq!(verified, true);
}


fn criterion_benchmark_pairing(c: &mut Criterion) {
    use ark_std::{UniformRand, ops::Mul};

    use ark_bls12_381::{Fr as ScalarField};


    use ntat::client_pairing::*;
    use ntat::server_pairing::*;
    use ntat::util_pairing::*;

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
    let mut server = Server::new(&pp, pk_c, rand_state);

    c.bench_function("Client Query w/Pairing", |b| b.iter(|| client.client_query(&mut rng, &pp, sk_c, pk_s)));

    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);

    c.bench_function("Server Issue w/Pairing", |b| b.iter(|| server_issue(&mut rng, &pp, sk_s, pk_c, &query)));
    let response = server.server_issue(&mut rng, &pp, sk_s, pk_c, &query);

    let r = response.unwrap();
    c.bench_function("Client Final w/Pairing", |b| b.iter(|| client.client_final(&r)));
    let token = client.client_final(&r);
    let extracted_token = token.unwrap();

    c.bench_function("Client Prove Redemption Part 1 w/Pairing", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s)));
    let proof1 = client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s);

    c.bench_function("Server Verify Redemption Part 1 w/Pairing", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &extracted_token, pk_s, &proof1)));
    let c_ = server.server_verify_redemption1(&mut rng, &extracted_token, pk_s, &proof1);

    c.bench_function("Client Prove Redemption Part 2 w/Pairing", |b| b.iter(|| client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap())));
    let proof2 = client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap());

    c.bench_function("Server Verify Redemption Part 2 w/Pairing", |b| b.iter(|| server.server_verify_redemption2(&extracted_token, sk_s, &proof2)));
    let verified = server.server_verify_redemption2(&extracted_token, sk_s, &proof2);

    assert_eq!(verified, true);
}

criterion_group!(benches, criterion_benchmark, criterion_benchmark_pairing);
criterion_main!(benches);