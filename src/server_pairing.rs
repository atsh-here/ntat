use ark_std::{UniformRand, ops::Mul};

use ark_ec::{pairing::Pairing};
use ark_bls12_381::{Bls12_381,Fr as ScalarField};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

use crate::util_pairing::*;

pub struct Server {
    pub pp: PublicParams,
    pub pk_c: Projective<g1config>,
    pub sigma_: Projective<g1config>,
    pub comm: ScalarField,
    pub c: ScalarField
}

impl Server {
    pub fn new(pp: &PublicParams, pk_c: Projective<g1config>, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        let server_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        let rand_g = pp.g1;
        Server { pp: server_pp, pk_c, sigma_: rand_g, comm: st, c: st }
    }

    pub fn server_issue(&self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        sk_s: ScalarField, 
        pk_c: Projective<g1config>,
        query: &Query) -> Option<ResponsePairing> {
    
        let verified = rep3_verify(&pp, pk_c, query.T, &query.pi_c);
        if !verified {
        return None;
        }
    
        let s = ScalarField::rand(rng);
        let S = query.T.mul((sk_s+s).inverse().unwrap());
    
        return Some(ResponsePairing { s, S });
    }

    pub fn server_verify_redemption1(
        &mut self,
        rng: &mut ThreadRng,  
        token: &Token, 
        pk_s: Projective<g2config>,
        proof: &RedemptionProof1) -> Option<ScalarField> {

        self.comm = proof.comm;
        self.sigma_ = proof.sigma_;

        if Bls12_381::pairing(token.sigma, pk_s) != Bls12_381::pairing(proof.sigma_, self.pp.g2) {
            return None;
        } else {
            let c = ScalarField::rand(rng);
            self.c = c;
            return Some(c);
        }

    }

    pub fn server_verify_redemption2(
        &self,
        token: &Token,
        sk_s: ScalarField,
        proof: &RedemptionProof2) -> bool {

        let Q_ =  self.pp.g1 * proof.v0 +  self.pp.g3 * proof.v1 + token.sigma * proof.v2;
        let Q_s = Q_ -  (self.sigma_ - self.pp.g4)* self.c;
        let d = [proof.rho.to_string(), Q_s.to_string()].concat();

        let ch = digest(d);
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H1 Failed");
        let comm_s = ScalarField::from_be_bytes_mod_order(&decoded);
        
        return comm_s == self.comm;
    }
    

}