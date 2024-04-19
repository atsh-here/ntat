use ark_std::{UniformRand, ops::Mul};

use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_bls12_381::{Bls12_381, G1Projective as G, Fr as ScalarField};
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

use crate::util_chac::*;

pub struct Server {
    
}

impl Server {
    pub fn new() -> Self {
        Server {}
    }

    pub fn server_issue(&self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        nonce: ScalarField, 
        query: &Query) -> Option<Response> {
        let ch = digest(nonce.to_string());
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Server CHAC");
        let h = pp.g1*ScalarField::from_be_bytes_mod_order(&decoded);

        if Bls12_381::pairing(query.s1, pp.g2) != Bls12_381::pairing(pp.g1, query.s2) {
            return None;
        } 
        if Bls12_381::pairing(query.sig, pp.g2) != Bls12_381::pairing(pp.pk2, pp.y2) + Bls12_381::pairing(h, query.s2) {
            return None;
        } 
        // F(pk_2) with key
        let key = ScalarField::rand(rng);
        let ch = digest([key.to_string(), pp.pk2.to_string()].concat());
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Server CHAC");
        let y = ScalarField::from_be_bytes_mod_order(&decoded);
        let yinv = y.inverse().unwrap();

        let z = (pp.pk1*pp.x1 + pp.pk2*pp.x2)*y;
        let w1 = pp.g1*yinv;
        let w2 = pp.g2*yinv;

        let ch = digest(pp.ipk1.to_string());
        let mut decoded = [0; 32];
        hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Server CHAC");
        let h_ipk = pp.g2*ScalarField::from_be_bytes_mod_order(&decoded);
        let v = h_ipk*yinv;
        
        return Some(Response{w1, w2, z, v});

    }

    pub fn server_redeem(&self,
        rng : &mut ThreadRng, 
        pp: &PublicParams, 
        nonce: ScalarField, 
        msg: &Msg) -> bool {
            let ch = digest(nonce.to_string());
            let mut decoded = [0; 32];
            hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Server CHAC");
            let h = pp.g1*ScalarField::from_be_bytes_mod_order(&decoded);
            
            if Bls12_381::pairing(msg.s1p, pp.g2) != Bls12_381::pairing(pp.g1, msg.s2p) {
                return false;
            } 
            
            if Bls12_381::pairing(msg.sigp, pp.g2) != Bls12_381::pairing(msg.pkp2, pp.y2) + Bls12_381::pairing(h, msg.s2p) {
                return false;
            } 
            
            if Bls12_381::pairing(msg.pkp1, pp.ipk1) + Bls12_381::pairing(msg.pkp2, pp.ipk2)  != Bls12_381::pairing(msg.zp, msg.w2p) {
                return false;
            } 
            
            if Bls12_381::pairing(msg.w1p, pp.g2) != Bls12_381::pairing(pp.g1, msg.w2p) {
                return false;
            } 
            
            let ch = digest(pp.ipk1.to_string());
            let mut decoded = [0; 32];
            hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H(nonce) Failed at Server CHAC");
            let h_ipk = pp.g2*ScalarField::from_be_bytes_mod_order(&decoded);
            
            if Bls12_381::pairing(msg.w1p, h_ipk) != Bls12_381::pairing(pp.g1, msg.vp) {
                return false;
            } 
            
            return true;
        }

}