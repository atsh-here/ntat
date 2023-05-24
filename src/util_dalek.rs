use curve25519_dalek_ng::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use curve25519_dalek_ng::scalar::Scalar as ScalarField;
use rand::rngs::ThreadRng;

use sha2::{Digest, Sha256};

pub struct PublicParams {
    pub g1: RistrettoPoint,
    pub g2: RistrettoPoint,
    pub g3: RistrettoPoint,
    pub g4: RistrettoPoint,
}

impl PublicParams {
    // pub fn to_string(&self) -> String {
    //     return [self.g1.to_string() , self.g2.to_string() , self.g3.to_string() , self.g4.to_string()].concat();
    // }

    pub fn hash(&self, h: &mut Sha256) {
        h.update(&self.g1.compress().to_bytes());
        h.update(&self.g2.compress().to_bytes());
        h.update(&self.g3.compress().to_bytes());
        h.update(&self.g4.compress().to_bytes());
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
    pub T: RistrettoPoint,
    pub pi_c: REP3Proof
}

#[derive(Debug)]
pub struct Response {
    pub s: ScalarField,
    pub S: RistrettoPoint,
    pub pi_s: DLEQProof
}

#[derive(Debug)]
pub struct ResponsePairing {
    pub s: ScalarField,
    pub S: RistrettoPoint,
}

#[derive(Debug)]
pub struct DLEQProof {
    pub ch: ScalarField,
    pub resp: ScalarField
}

#[derive(Debug)]
pub struct Token {
    pub sigma: RistrettoPoint,
    pub r: ScalarField,
    pub s: ScalarField
}

#[derive(Debug)]
pub struct RedemptionProof1 {
    pub sigma_: RistrettoPoint,
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
    let g1 = RistrettoPoint::random(rng);;
    let g2 = RistrettoPoint::random(rng);;
    let g3 = RistrettoPoint::random(rng);;
    let g4 = RistrettoPoint::random(rng);;
    let pp = PublicParams{g1, g2, g3, g4};
    return pp
}

pub fn rep3_prove(rng : &mut ThreadRng, 
                pp: &PublicParams, 
                X: RistrettoPoint, 
                T: RistrettoPoint,
                x: ScalarField,
                lambda: ScalarField, 
                r: ScalarField) -> REP3Proof {

    let a = ScalarField::random(rng);
    let b = ScalarField::random(rng);
    let c = ScalarField::random(rng);


    let comm1 = pp.g1 * a;
    //let comm2 = pp.g1 * a + pp.g3 * b + T * c; // without msm
    let comm2 = RistrettoPoint::multiscalar_mul([a, b, c], [pp.g1, pp.g3, T]);

    // let d = [pp.to_string(), X.to_string(), T.to_string(), comm1.to_string(), comm2.to_string()].concat();
    // let ch = digest(d);
    // let mut decoded = [0; 32];
    // hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H1 Failed");
    let mut h = Sha256::new();

    pp.hash(&mut h);
    h.update(&X.compress().to_bytes());
    h.update(&T.compress().to_bytes());
    h.update(&comm1.compress().to_bytes());
    h.update(&comm2.compress().to_bytes());
    let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H1");

    let ch = ScalarField::from_bytes_mod_order(digest);

    let resp1 = a - ch*x;
    let resp2 = b - ch*r;
    let resp3 = c + ch*lambda.invert();

    return REP3Proof{ch, resp1, resp2, resp3}

}

pub fn rep3_verify(pp: &PublicParams, X: RistrettoPoint, T: RistrettoPoint, pi_c: &REP3Proof) -> bool{

    let comm1_ = pp.g1 * pi_c.resp1 + X * pi_c.ch;
    //let comm2_ = pp.g1 * pi_c.resp1 + pp.g3*pi_c.resp2 + T*pi_c.resp3 - pp.g4*pi_c.ch; // without msm
    let comm2_ = RistrettoPoint::multiscalar_mul([pi_c.resp1, pi_c.resp2, pi_c.resp3, -pi_c.ch], [pp.g1, pp.g3, T, pp.g4]);
    let mut h = Sha256::new();

    pp.hash(&mut h);
    h.update(&X.compress().to_bytes());
    h.update(&T.compress().to_bytes());
    h.update(&comm1_.compress().to_bytes());
    h.update(&comm2_.compress().to_bytes());
    let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H1");
    let ch_ = ScalarField::from_bytes_mod_order(digest);

    return pi_c.ch == ch_;
}

pub fn dleq_prove(rng: &mut ThreadRng,
    pp: &PublicParams, 
    Y: RistrettoPoint,
    S: RistrettoPoint,
    T: RistrettoPoint,
    s: ScalarField,
    y: ScalarField) -> DLEQProof{

    let a = ScalarField::random(rng);
    let comm1 = pp.g2*a;
    let comm2 = S*a;
    let ss = S*s;

    let mut h = Sha256::new();

    pp.hash(&mut h);
    h.update(&Y.compress().to_bytes());
    h.update(&S.compress().to_bytes());
    h.update(&(T - ss).compress().to_bytes());
    h.update(&comm1.compress().to_bytes());
    h.update(&comm2.compress().to_bytes());
    let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H1");

    let ch = ScalarField::from_bytes_mod_order(digest);

    let resp = a  + ch*y;

    return DLEQProof {ch, resp}
}

pub fn dleq_verify(pp: &PublicParams, 
    Y: RistrettoPoint, 
    S: RistrettoPoint, 
    T: RistrettoPoint, 
    s: ScalarField,
    pi_s: &DLEQProof) -> bool{

    let inter = T - S*s;
    let comm1_ = pp.g2*pi_s.resp - Y*pi_s.ch;
    let comm2_ = S*pi_s.resp - inter*pi_s.ch;


    let mut h = Sha256::new();

    pp.hash(&mut h);
    h.update(&Y.compress().to_bytes());
    h.update(&S.compress().to_bytes());
    h.update(&inter.compress().to_bytes());
    h.update(&comm1_.compress().to_bytes());
    h.update(&comm2_.compress().to_bytes());
    let digest: [u8; 32] = h.finalize().as_slice().try_into().expect("Invalid H1");

    let ch_ = ScalarField::from_bytes_mod_order(digest);

    return pi_s.ch == ch_;
}