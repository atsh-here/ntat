use ark_std::{UniformRand, ops::Mul};

use ark_bls12_381::{g2, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::{short_weierstrass::Projective, VariableBaseMSM, CurveGroup};
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use ark_ff::fields::{PrimeField, Field};



pub struct PublicParams {
    pub g1: Projective<g1config>,
    pub g2: Projective<g2config>,
    pub y1: Projective<g1config>,
    pub y2: Projective<g2config>,
    pub sk: Projective<g1config>,
    pub pk1: Projective<g1config>,
    pub pk2: Projective<g1config>,
    pub x1: ScalarField,
    pub x2: ScalarField,
    pub ipk1: Projective<g2config>,
    pub ipk2: Projective<g2config>
}

impl PublicParams {
    pub fn to_string(&self) -> String {
        return [self.g1.to_string() , self.g2.to_string()].concat();
    }
}

pub fn setup(rng : &mut ThreadRng) -> PublicParams {
    let g1 = G::rand(rng);
    let g2 = G2::rand(rng);
    let delta = ScalarField::rand(rng);
    let y1 = g1.mul(delta);
    let y2 = g2.mul(delta);

    let alpha = ScalarField::rand(rng);
    let sk = y1.mul(alpha);
    let pk1 = g1; // copy
    let pk2 = g1.mul(alpha);

    let x1 = ScalarField::rand(rng);
    let x2 = ScalarField::rand(rng);

    let ipk1 = g2.mul(x1);
    let ipk2 = g2.mul(x2);

    let pp = PublicParams{g1, g2, y1, y2, sk, pk1, pk2, x1, x2, ipk1, ipk2};
    return pp
}


pub struct Query {
    pub pk2: Projective<g1config>,
    pub sig: Projective<g1config>,
    pub s1: Projective<g1config>,
    pub s2: Projective<g2config>
}

pub struct Response {
    pub w1: Projective<g1config>,
    pub w2: Projective<g2config>,
    pub z: Projective<g1config>,
    pub v: Projective<g2config>
}

pub struct Msg{
    pub pkp1: Projective<g1config>,
    pub pkp2: Projective<g1config>,
    pub sigp: Projective<g1config>,
    pub s1p: Projective<g1config>,
    pub s2p: Projective<g2config>,
    pub zp: Projective<g1config>,
    pub w1p: Projective<g1config>,
    pub w2p: Projective<g2config>,
    pub vp: Projective<g2config>
}