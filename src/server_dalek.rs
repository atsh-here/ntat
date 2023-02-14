use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use rand::rngs::ThreadRng;

use sha2::{Digest, Sha256};

use crate::util_dalek::{RedemptionProof1, RedemptionProof2};
use crate::util_dalek::{PublicParams, Query, DLEQProof, Response, Token, rep3_verify,  dleq_prove};

pub struct Server {
    pub pp: PublicParams,
    pub pk_c: RistrettoPoint,
    pub sigma_: RistrettoPoint,
    pub comm: ScalarField,
    pub c: ScalarField
}

impl Server {
    pub fn new(pp: &PublicParams, pk_c: RistrettoPoint, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        let server_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        let rand_g = pp.g1;
        Server { pp: server_pp, pk_c, sigma_: rand_g, comm: st, c: st }
    }

    pub fn server_issue(&self,
        rng: &mut ThreadRng, 
        pp: &PublicParams, 
        sk_s: ScalarField, 
        pk_c: RistrettoPoint,
        query: &Query) -> Option<Response> {
    
        let verified = rep3_verify(&pp, pk_c, query.T, &query.pi_c);
        if !verified {
        return None;
        }
    
        let s = ScalarField::random(rng);
        let S = query.T*(sk_s+s).invert();
    
        let Y = pp.g2*sk_s;
        let pi_s: DLEQProof = dleq_prove(rng, &pp, Y, S, query.T, s, sk_s);
        return Some(Response { s, S, pi_s });
    }
    
    pub fn server_verify_redemption1(
        &mut self,
        rng: &mut ThreadRng,  
        token: &Token, 
        sk_s: ScalarField,
        proof: &RedemptionProof1) -> Option<ScalarField> {

        self.comm = proof.comm;
        self.sigma_ = proof.sigma_;

        if proof.sigma_ != token.sigma * sk_s {
            return None;
        } else {
            let c = ScalarField::random(rng);
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


        let mut h = Sha256::new();
        h.update(&proof.rho.to_bytes());
        h.update(&Q_s.compress().to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H1");

        let comm_s = ScalarField::from_bytes_mod_order(digest);
        
        return comm_s == self.comm;
    }
    

}