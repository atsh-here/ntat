use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benchmark_pairing(c: &mut Criterion) {
    use ark_std::{UniformRand, ops::Mul};

    use ark_bls12_381::Fr as ScalarField;


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

    c.bench_function("NTAT w/Pairing: Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, sk_c, pk_s)));

    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);

    c.bench_function("NTAT w/Pairing: Server Issue", |b| b.iter(|| server_issue(&mut rng, &pp, sk_s, pk_c, &query)));
    let response = server.server_issue(&mut rng, &pp, sk_s, pk_c, &query);

    let r = response.unwrap();
    c.bench_function("NTAT w/Pairing: Client Finalize Query", |b| b.iter(|| client.client_final(&r)));
    let token = client.client_final(&r);
    let extracted_token = token.unwrap();

    c.bench_function("NTAT w/Pairing: Client Redeem Part 1", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s)));
    let proof1 = client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s);

    c.bench_function("NTAT w/Pairing: Server Verify Redemption", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &extracted_token, pk_s, &proof1)));
    let c_ = server.server_verify_redemption1(&mut rng, &extracted_token, pk_s, &proof1);

    c.bench_function("NTAT w/Pairing: Client Redeem Part 2", |b| b.iter(|| client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap())));
    let proof2 = client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap());

    c.bench_function("NTAT w/Pairing: Server Verify Redemption Part 2", |b| b.iter(|| server.server_verify_redemption2(&extracted_token, sk_s, &proof2)));
    let verified = server.server_verify_redemption2(&extracted_token, sk_s, &proof2);

    assert!(verified);

}



criterion_group!(benches, criterion_benchmark_pairing);
criterion_main!(benches);
