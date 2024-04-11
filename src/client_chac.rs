use ark_std::UniformRand;

use ark_bls12_381::Fr as ScalarField;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

use crate::util_chac::*;

pub struct Client {

}

impl Client {
    pub fn new() -> Self {
        Client{}
    }

    pub fn client_query(&mut self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        nonce: ScalarField) -> Query {

        //let h = HashToCurve::hash(&self, nonce).unwrap();

        let ch = digest(nonce.to_string());
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Client CHAC");
        let h = pp.g1*ScalarField::from_be_bytes_mod_order(&decoded);
        let r = ScalarField::rand(rng);
        let s1 = pp.g1*r;
        let s2 = pp.g2*r;
        let sig = pp.sk + h*r;

        return Query{pk2: pp.pk2, sig, s1, s2};
    }

    pub fn client_redeem(&mut self,
        rng: &mut ThreadRng,
        pp: &PublicParams,
        nonce: ScalarField,
        resp: &Response) -> Msg {
            let ch = digest(nonce.to_string());
            let mut decoded = [0; 32];
            hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Client Redeem CHAC");
            let h = pp.g1*ScalarField::from_be_bytes_mod_order(&decoded);
            let rp = ScalarField::rand(rng);
            let kdp = ScalarField::rand(rng);
            let psi = ScalarField::rand(rng);
            
            let s1p = pp.g1*kdp;
            let s2p = pp.g2*kdp;

            let sigp = pp.sk*rp + h*kdp;

            let pkp1 = pp.g1*rp; // A'
            let pkp2 = pp.pk2*rp; // B'
            let zp = resp.z*rp*psi;

            let psi_inv =  psi.inverse().unwrap();
            let w1p = resp.w1*psi_inv;
            let w2p = resp.w2*psi_inv;

            let vp = resp.v*psi_inv;

            Msg{pkp1, pkp2, sigp, s1p, s2p, zp, w1p, w2p, vp}
        }

}
