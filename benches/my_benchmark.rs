use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benchmark_dalek(c: &mut Criterion) {
    use curve25519_dalek_ng::scalar::Scalar as ScalarField;

    use ntat::server_dalek::*;
    use ntat::client_dalek::*;
    use ntat::util_dalek::*;

    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let sk_c = ScalarField::random(&mut rng);
    let pk_c = pp.g1*sk_c;

    // Server KeyGen
    let sk_s = ScalarField::random(&mut rng);
    let pk_s = pp.g2*sk_s;

    let rand_state = ScalarField::random(&mut rng);
    let rand_server_state = ScalarField::random(&mut rng);
    let mut client = Client::new(&pp, pk_s, rand_state);
    let mut server = Server::new(&pp, pk_c, rand_server_state);

    c.bench_function("NTAT: Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, sk_c, pk_s)));

    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);

    c.bench_function("NTAT: Server Issue", |b| b.iter(|| server.server_issue(&mut rng, &pp, sk_s, pk_c, &query)));
    let response = server.server_issue(&mut rng, &pp, sk_s, pk_c, &query);

    let r = response.unwrap();
    c.bench_function("NTAT: Client Finalize Query", |b| b.iter(|| client.client_final(&r)));
    let token = client.client_final(&r);
    let extracted_token = token.unwrap();

    c.bench_function("NTAT: Client Redeem Part 1", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s)));
    let proof1 = client.client_prove_redemption1(&mut rng, &extracted_token, sk_c, pk_s);

    c.bench_function("NTAT: Server Verify Redemption Part 1", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &extracted_token, sk_s, &proof1)));
    let c_ = server.server_verify_redemption1(&mut rng, &extracted_token, sk_s, &proof1);

    c.bench_function("NTAT: Client Redeem Part 2", |b| b.iter(|| client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap())));
    let proof2 = client.client_prove_redemption2(&mut rng, &extracted_token, sk_c, c_.unwrap());

    c.bench_function("NTAT: Server Verify Redemption Part 2", |b| b.iter(|| server.server_verify_redemption2(&extracted_token, sk_s, &proof2)));
    let verified = server.server_verify_redemption2(&extracted_token, sk_s, &proof2);

    assert!(verified);
}


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

fn criterion_benchmark_u_prove(c: &mut Criterion) {

    use curve25519_dalek_ng::scalar::Scalar as ScalarField;

    use ntat::server_u_prove::*;
    use ntat::client_u_prove::*;
    use ntat::util_u_prove::*;

    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let sk_c = ScalarField::random(&mut rng);
    let pk_c = pp.gd * sk_c;

    // Server KeyGen
    let sk_s = ScalarField::random(&mut rng);
    let pk_s = pp.g0 * sk_s.invert();

    let pi = ScalarField::random(&mut rng);
    let rand_state = ScalarField::random(&mut rng);
    let mut client = Client::new(&pp, sk_c, pk_c, pi, rand_state);
    let mut server = Server::new(&pp, pk_c, sk_s, pk_s, rand_state);

    c.bench_function("U-Prove: Server Initiate", |b| b.iter(|| server.server_initiate(&mut rng, &pp)));
    let message = server.server_initiate(&mut rng, &pp);

    c.bench_function("U-Prove: Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, pk_s, &message)));
    let sigma_c = client.client_query(&mut rng, &pp, pk_s, &message);

    c.bench_function("U-Prove: Server Issue", |b| b.iter(|| server.server_issue(sigma_c)));
    let sigma_r = server.server_issue(sigma_c);

    c.bench_function("U-Prove: Client Finalize Query", |b| b.iter(|| server.server_initiate(&mut rng, &pp)));
    let token = client.client_final(&pp, pk_s, sigma_r);

    let (token, witness) = token.unwrap();

    c.bench_function("U-Prove: Client Redeem Part 1", |b| b.iter(|| client.client_prove_redemption1(&mut rng, &pp, &token)));
    let proof1 = client.client_prove_redemption1(&mut rng, &pp, &token);

    c.bench_function("U-Prove: Server Verify Redemption Part 1", |b| b.iter(|| server.server_verify_redemption1(&mut rng, &pp, &proof1)));
    let a = server.server_verify_redemption1(&mut rng, &pp, &proof1);
    let a = a.unwrap();

    c.bench_function("U-Prove: Client Redeem Part 2", |b| b.iter(|| client.client_prove_redemption2(&token, a)));
    let proof2 = client.client_prove_redemption2(&token, a);

    c.bench_function("U-Prove: Server Verify Redemption Part 2", |b| b.iter(|| server.server_verify_redemption2(&token, &pp, &proof2)));
    let verified = server.server_verify_redemption2(&token, &pp, &proof2);

    assert!(verified);

}

fn criterion_benchmark_chac(c: &mut Criterion) {
    use ark_std::UniformRand;

    use ark_bls12_381::Fr as ScalarField;


    use ntat::client_chac::*;
    use ntat::server_chac::*;
    use ntat::util_chac::*;

    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);

    // Client KeyGen
    let nonce = ScalarField::rand(&mut rng);
 
    let mut client = Client::new();
    let mut server = Server::new();
    c.bench_function("CHAC: Client Query", |b| b.iter(|| client.client_query(&mut rng, &pp, nonce)));

    let query = client.client_query(&mut rng, &pp, nonce);
    c.bench_function("CHAC: Server Issue", |b| b.iter(|| server.server_issue(&mut rng, &pp, nonce, &query)));

    let resp = server.server_issue(&mut rng, &pp, nonce, &query);
    assert!(resp.is_some());
    let resp = resp.unwrap();

    c.bench_function("CHAC: Client Redeem", |b| b.iter(|| client.client_redeem(&mut rng, &pp, nonce, &resp)));
    let msg = client.client_redeem(&mut rng, &pp, nonce, &resp);

    c.bench_function("CHAC: Server Redeem", |b| b.iter(|| server.server_redeem(&mut rng, &pp, nonce, &msg)));
    let verified = server.server_redeem(&mut rng, &pp, nonce, &msg);
    
    assert!(verified)
}


criterion_group!(benches, criterion_benchmark_dalek, criterion_benchmark_pairing, criterion_benchmark_u_prove, criterion_benchmark_chac);
criterion_main!(benches);