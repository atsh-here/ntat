use ark_std::{UniformRand, ops::Mul};

use ark_ec::short_weierstrass::Projective;
use ark_secp256k1::Projective as G;
use ark_secp256k1::Config;
use ark_secp256k1::Fr as ScalarField;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};



pub struct PublicParams {
    pub g1: Projective<Config>,
    pub g2: Projective<Config>,
    pub g3: Projective<Config>,
    pub g4: Projective<Config>,
}

impl PublicParams {
    pub fn to_string(&self) -> String {
        return [self.g1.to_string() , self.g2.to_string() , self.g3.to_string() , self.g4.to_string()].concat();
    }
}

#[derive(Debug)]
pub struct REP3Proof {
    pub ch: ScalarField,
    pub resp1: ScalarField,
    pub resp2: ScalarField,
    pub resp3: ScalarField
}

#[derive(Debug)]
pub struct Query {
    pub T: Projective<Config>,
    pub pi_c: REP3Proof
}

#[derive(Debug)]
pub struct Response {
    pub s: ScalarField,
    pub S: Projective<Config>,
    pub pi_s: DLEQProof
}

#[derive(Debug)]
pub struct ResponsePairing {
    pub s: ScalarField,
    pub S: Projective<Config>,
}

#[derive(Debug)]
pub struct DLEQProof {
    pub ch: ScalarField,
    pub resp: ScalarField
}

#[derive(Debug)]
pub struct Token {
    pub sigma: Projective<Config>,
    pub r: ScalarField,
    pub s: ScalarField
}

#[derive(Debug)]
pub struct RedemptionProof1 {
    pub sigma_: Projective<Config>,
    pub comm: ScalarField,
}

#[derive(Debug)]
pub struct RedemptionProof2 {
    pub v0: ScalarField,
    pub v1: ScalarField,
    pub v2: ScalarField,
    pub rho: ScalarField
}





pub fn setup(rng : &mut ThreadRng) -> PublicParams {
    let g1 = G::rand(rng);
    let g2 = G::rand(rng);
    let g3 = G::rand(rng);
    let g4 = G::rand(rng);
    let pp = PublicParams{g1, g2, g3, g4};
    return pp
}

pub fn hash(input: &String, sep: &str) -> ScalarField {
    let ch = digest(sep.to_owned() + input);
    let mut decoded = [0; 32];
    hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H Failed");
    let ch = ScalarField::from_be_bytes_mod_order(&decoded);
    return ch;
}


pub fn server_issue(
    rng : &mut ThreadRng, 
    pp: &PublicParams, 
    sk_s: ScalarField, 
    pk_c: Projective<Config>,
    query: &Query) -> Option<Response> {

    let verified = rep3_verify(&pp, pk_c, query.T, &query.pi_c);
    if !verified {
    return None;
    }

    let s = ScalarField::rand(rng);
    let S = query.T.mul((sk_s+s).inverse().unwrap());

    let Y = pp.g2*sk_s;
    let pi_s: DLEQProof = dleq_prove(rng, &pp, Y, S, query.T, s, sk_s);
    return Some(Response { s, S, pi_s });
}


pub fn rep3_prove(rng : &mut ThreadRng, 
                pp: &PublicParams, 
                X: Projective<Config>, 
                T: Projective<Config>,
                x: ScalarField,
                lambda: ScalarField, 
                r: ScalarField) -> REP3Proof {

    let a = ScalarField::rand(rng);
    let b = ScalarField::rand(rng);
    let c = ScalarField::rand(rng);


    let comm1 = pp.g1.mul(a);
    let comm2 = pp.g1.mul(a) + pp.g3.mul(b) + T.mul(c);
    let d = [pp.to_string(), X.to_string(), T.to_string(), comm1.to_string(), comm2.to_string()].concat();
    let ch = digest(d);
    let mut decoded = [0; 32];
    hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H1 Failed");
    let ch = ScalarField::from_be_bytes_mod_order(&decoded);

    let resp1 = a - ch*x;
    let resp2 = b - ch*r;
    let resp3 = c + ch*lambda.inverse().unwrap();

    return REP3Proof{ch, resp1, resp2, resp3}

}

pub fn rep3_verify(pp: &PublicParams, X: Projective<Config>, T: Projective<Config>, pi_c: &REP3Proof) -> bool{

    let comm1_ = pp.g1.mul(pi_c.resp1) + X.mul(pi_c.ch);
    let comm2_ = pp.g1.mul(pi_c.resp1) + pp.g3.mul(pi_c.resp2) + T.mul(pi_c.resp3) - pp.g4.mul(pi_c.ch);

    let h = digest([pp.to_string(), X.to_string(), T.to_string(), comm1_.to_string(), comm2_.to_string()].concat());
    let mut decoded = [0; 32];
    hex::decode_to_slice(h, &mut decoded).expect("Decoding H1 Failed");
    let ch_ = ScalarField::from_be_bytes_mod_order(&decoded);

    return pi_c.ch == ch_;
}

pub fn dleq_prove(rng: &mut ThreadRng,
    pp: &PublicParams, 
    Y: Projective<Config>,
    S: Projective<Config>,
    T: Projective<Config>,
    s: ScalarField,
    y: ScalarField) -> DLEQProof{

    let a = ScalarField::rand(rng);
    let comm1 = pp.g2.mul(a);
    let comm2 = S.mul(a);
    let ss = S.mul(s);
    let d = [pp.to_string(), Y.to_string(), S.to_string(), (T- ss).to_string(), comm1.to_string(), comm2.to_string()].concat();
    let ch = digest(d);
    let mut decoded = [0; 32];
    hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H2 Failed");
    let ch = ScalarField::from_be_bytes_mod_order(&decoded);

    let resp = a  + ch*y;

    return DLEQProof {ch, resp}
}

pub fn dleq_verify(pp: &PublicParams, 
    Y: Projective<Config>, 
    S: Projective<Config>, 
    T: Projective<Config>, 
    s: ScalarField,
    pi_s: &DLEQProof) -> bool{

    let inter = T - S.mul(s);
    let comm1_ = pp.g2.mul(pi_s.resp) - Y.mul(pi_s.ch);
    let comm2_ = S.mul(pi_s.resp) - inter.mul(pi_s.ch);


    let h = digest([pp.to_string(), Y.to_string(), S.to_string(), inter.to_string(), comm1_.to_string(), comm2_.to_string()].concat());
    let mut decoded = [0; 32];
    hex::decode_to_slice(h, &mut decoded).expect("Decoding H2 Failed");
    let ch_ = ScalarField::from_be_bytes_mod_order(&decoded);

    return pi_s.ch == ch_;
}