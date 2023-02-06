
use ark_std::{UniformRand, ops::Mul};

use ark_bls12_381::{Bls12_381, G1Projective as G, G1Affine as GAffine, G2Projective as G2, Fr as ScalarField, Fq as F};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

pub mod util;
pub mod client;
pub mod client_pairing;
pub mod server;
pub mod server_pairing;
pub mod util_pairing;

use crate::client::*;
use crate::util_pairing::*;


