use ark_std::{UniformRand, ops::Mul, One};

use ark_ec::{pairing::Pairing, VariableBaseMSM, CurveGroup};
use ark_bls12_381::{Bls12_381, G1Projective as G, Fr as ScalarField};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

use crate::util_pairing::*;

pub struct Client {
    pub pp: PublicParams,
    pub pk_s: Projective<g2config>,
    pub r: ScalarField, 
    pub lambda: ScalarField,
    pub T: Projective<g1config>,
    pub alpha: ScalarField,
    pub beta: ScalarField,
    pub gamma: ScalarField,
    pub rho: ScalarField
}

impl Client {
    pub fn new(pp: &PublicParams, pk_s: Projective<g2config>, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        let client_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        Client { pp: client_pp, pk_s, r: st, lambda: st, T: pp.g1, alpha: st, beta: st, gamma: st, rho: st }
    }

    pub fn client_query(&mut self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        sk_c: ScalarField, 
        pk_s: Projective<g2config>) -> Query {

        let X = pp.g1*sk_c;
        let r = ScalarField::rand(rng);
        let lambda = ScalarField::rand(rng);
        let T = (X + pp.g3*r + pp.g4)*lambda;
        //let T_ = G::msm(&[pp.g1.into_affine(), pp.g3.into_affine(), pp.g4.into_affine()], &[sk_c*lambda, r*lambda, lambda]).unwrap();
        //assert_eq!(T, T_);
        let pi_c: REP3Proof = rep3_prove(rng, &pp, X, T, sk_c, lambda, r);
        
        self.update_state(r, lambda, T);

        return Query{T, pi_c};
    }

    pub fn update_state(&mut self, r: ScalarField, lambda: ScalarField, T: Projective<g1config> ) {
        self.r = r;
        self.lambda = lambda;
        self.T = T;
    }

    pub fn client_final(&self, resp: &ResponsePairing) -> Option<Token> {
        let p1 = Bls12_381::pairing(resp.S, self.pk_s + self.pp.g2*resp.s);
        let p2 = Bls12_381::pairing(self.T, self.pp.g2);
        let verified = p1 == p2;
        
        if !verified {
            return None;
        }

        let sigma = resp.S.mul(self.lambda.inverse().unwrap());

        return Some(Token { sigma, r: self.r , s: resp.s });
    }

    pub fn client_prove_redemption1(
        &mut self,
        rng : &mut ThreadRng, 
        token: &Token, 
        sk_c: ScalarField, 
        pk_s: Projective<g2config>) -> RedemptionProof1 {

        // let sigma_ = self.pp.g1 * sk_c + self.pp.g3 * token.r + self.pp.g4 - token.sigma * token.s;
        let sigma_ = G::msm(&[self.pp.g1.into_affine(), self.pp.g3.into_affine(), self.pp.g4.into_affine(), token.sigma.into_affine()], &[sk_c, token.r, ScalarField::one(), -token.s]).unwrap();
        let (alpha, beta, gamma) = (ScalarField::rand(rng), ScalarField::rand(rng), ScalarField::rand(rng)) ;
        // let Q = self.pp.g1 * alpha + self.pp.g3 * beta + token.sigma * gamma;
        let Q = G::msm(&[self.pp.g1.into_affine(), self.pp.g3.into_affine(), token.sigma.into_affine()], &[alpha, beta, gamma]).unwrap();
        let rho = ScalarField::rand(rng);
        let d = [rho.to_string(), Q.to_string()].concat();

        let ch = digest(d);
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H1 Failed");
        let comm = ScalarField::from_be_bytes_mod_order(&decoded);

        self.alpha = alpha;
        self.beta = beta;
        self.gamma = gamma;
        self.rho = rho;

        return RedemptionProof1 { sigma_, comm}
    }

    pub fn client_prove_redemption2(
        &self,
        rng : &mut ThreadRng, 
        token: &Token,
        sk_c: ScalarField, 
        c: ScalarField) -> RedemptionProof2 {
        
        let v0 = self.alpha + c*sk_c;
        let v1 = self.beta + c*token.r;
        let v2 = self.gamma - c*token.s;

        return RedemptionProof2 { v0, v1, v2, rho: self.rho};
    }

}