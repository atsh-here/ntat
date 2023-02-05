use ark_std::{UniformRand, ops::Mul};

use ark_bls12_381::{Bls12_381, G1Projective as G, G1Affine as GAffine, G2Projective as G2, Fr as ScalarField, Fq as F};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

use crate::util::*;

pub struct Client {
    pub pp: PublicParams,
    pub pk_s: Projective<g2config>,
    pub r: ScalarField, 
    pub lambda: ScalarField,
    pub T: Projective<g1config>
}

impl Client {
    pub fn new(pp: &PublicParams, pk_s: Projective<g2config>, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        let client_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        Client { pp: client_pp, pk_s, r: st, lambda: st, T: pp.g1 }
    }

    pub fn client_query(&mut self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        sk_c: ScalarField, 
        pk_s: Projective<g2config>) -> Query {

        let X = pp.g1.mul(sk_c);
        let r = ScalarField::rand(rng);
        let lambda = ScalarField::rand(rng);
        let T = (X + pp.g3.mul(r) + pp.g4).mul(lambda);
        let pi_c: REP3Proof = rep3_prove(rng, &pp, X, T, sk_c, lambda, r);
        
        self.update_state(r, lambda, T);

        return Query{T, pi_c};
    }

    pub fn update_state(&mut self, r: ScalarField, lambda: ScalarField, T: Projective<g1config> ) {
        self.r = r;
        self.lambda = lambda;
        self.T = T;
    }

    pub fn client_final(&self, resp: &Response) -> Option<Token> {
        let verified = dleq_verify(&self.pp, self.pk_s, resp.S, self.T, resp.s, &resp.pi_s);
        
        if !verified {
            return None;
        }

        let sigma = resp.S.mul(self.lambda.inverse().unwrap());

        return Some(Token { sigma, r: self.r , s: resp.s });
    }

}