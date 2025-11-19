use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use curve25519_dalek_ng::traits::MultiscalarMul;
use rand::rngs::ThreadRng;

use sha2::{Digest, Sha256};

use crate::util_dalek::{RedemptionProof1, RedemptionProof2};
use crate::util_dalek::{PublicParams, Query, REP3Proof, Response, Token, rep3_prove,  dleq_verify};

pub struct Client {
    pub pp: PublicParams,
    pub pk_s: RistrettoPoint,
    pub r: ScalarField, 
    pub lambda: ScalarField,
    pub T: RistrettoPoint,
    pub alpha: ScalarField,
    pub beta: ScalarField,
    pub gamma: ScalarField,
    pub rho: ScalarField
}

impl Client {
    pub fn new(pp: &PublicParams, pk_s: RistrettoPoint, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        
        let client_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        Client { pp: client_pp, pk_s, r: st, lambda: st, T: pp.g1, alpha: st, beta: st, gamma: st, rho: st}
    }

    pub fn client_query(&mut self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        sk_c: ScalarField, 
        pk_s: RistrettoPoint) -> Query {

        let X = pp.g1*sk_c;
        let r = ScalarField::random(rng);
        let lambda = ScalarField::random(rng);

        let T = RistrettoPoint::multiscalar_mul([sk_c*lambda, r*lambda, lambda],[pp.g1, pp.g3, pp.g4]);

        let pi_c: REP3Proof = rep3_prove(rng, &pp, X, T, sk_c, lambda, r);
        
        self.update_state(r, lambda, T);

        return Query{T, pi_c};
    }

    pub fn update_state(&mut self, r: ScalarField, lambda: ScalarField, T: RistrettoPoint ) {
        self.r = r;
        self.lambda = lambda;
        self.T = T;
    }

    pub fn client_final(&self, resp: &Response) -> Option<Token> {
        let verified = dleq_verify(&self.pp, self.pk_s, resp.S, self.T, resp.s, &resp.pi_s);
        
        if !verified {
            return None;
        }

        let sigma = resp.S*self.lambda.invert();

        return Some(Token { sigma, r: self.r , s: resp.s });
    }

    pub fn client_prove_redemption1(
        &mut self,
        rng : &mut ThreadRng, 
        token: &Token, 
        sk_c: ScalarField, 
        pk_s: RistrettoPoint) -> RedemptionProof1 {
        
        let scalars = [sk_c, token.r, ScalarField::one(), -token.s];
        let points = [self.pp.g1, self.pp.g3, self.pp.g4, token.sigma];
        let sigma_ = RistrettoPoint::multiscalar_mul(&scalars, &points);

        let (alpha, beta, gamma) = (ScalarField::random(rng), ScalarField::random(rng), ScalarField::random(rng)) ;
        //let Q = self.pp.g1 * alpha + self.pp.g3 * beta + token.sigma * gamma; // without msm
        let Q = RistrettoPoint::multiscalar_mul([alpha, beta, gamma], [self.pp.g1, self.pp.g3, token.sigma]);
        let rho = ScalarField::random(rng);

        let mut h = Sha256::new();
        h.update(&rho.to_bytes());
        h.update(&Q.compress().to_bytes());
        let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H3");

        let comm = ScalarField::from_bytes_mod_order(digest);

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