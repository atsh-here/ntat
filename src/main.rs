
use ark_std::{UniformRand, ops::Mul};

use ark_bls12_381::{Bls12_381, G1Projective as G, G1Affine as GAffine, G2Projective as G2, Fr as ScalarField, Fq as F};
use ark_ec::short_weierstrass::Projective;
use ark_bls12_381::g1::Config as g1config;
use ark_bls12_381::g2::Config as g2config;
use rand::rngs::ThreadRng;
use sha256::digest;
use ark_ff::fields::{PrimeField, Field};

struct PublicParams {
    g1: Projective<g1config>,
    g2: Projective<g2config>,
    g3: Projective<g1config>,
    g4: Projective<g1config>,
}

impl PublicParams {
    fn to_string(&self) -> String {
        return [self.g1.to_string() , self.g2.to_string() , self.g3.to_string() , self.g4.to_string()].concat();
    }
}

#[derive(Debug)]
struct REP3Proof {
    ch: ScalarField,
    resp1: ScalarField,
    resp2: ScalarField,
    resp3: ScalarField
}

#[derive(Debug)]
struct Query {
    T: Projective<g1config>,
    pi_c: REP3Proof
}

#[derive(Debug)]
struct Response {
    s: ScalarField,
    S: Projective<g1config>,
    pi_s: DLEQProof
}

#[derive(Debug)]
struct DLEQProof {
    ch: ScalarField,
    resp: ScalarField
}

#[derive(Debug)]
struct Token {
    sigma: Projective<g1config>,
    r: ScalarField,
    s: ScalarField
}

struct Client {
    pp: PublicParams,
    pk_s: Projective<g2config>,
    r: ScalarField, 
    lambda: ScalarField,
    T: Projective<g1config>
}

impl Client {
    fn new(pp: &PublicParams, pk_s: Projective<g2config>, st: ScalarField) -> Self {
        // initialize with pp and random state
        // temporarily set T to g1
        let client_pp = PublicParams{g1: pp.g1, g2: pp.g2, g3: pp.g3, g4: pp.g4};
        Client { pp: client_pp, pk_s, r: st, lambda: st, T: pp.g1 }
    }

    fn client_query(&mut self,
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

    fn update_state(&mut self, r: ScalarField, lambda: ScalarField, T: Projective<g1config> ) {
        self.r = r;
        self.lambda = lambda;
        self.T = T;
    }

    fn client_final(&self, resp: Response) -> Option<Token> {
        let verified = dleq_verify(&self.pp, self.pk_s, resp.S, self.T, resp.s, resp.pi_s);
        
        if !verified {
            return None;
        }

        let sigma = resp.S.mul(self.lambda.inverse().unwrap());

        return Some(Token { sigma, r: self.r , s: resp.s });
    }

}


fn setup(rng : &mut ThreadRng) -> PublicParams {
    let g1 = G::rand(rng);
    let g2 = G2::rand(rng);
    let g3 = G::rand(rng);
    let g4 = G::rand(rng);
    let pp = PublicParams{g1, g2, g3, g4};
    return pp
}





fn server_issue(rng : &mut ThreadRng, 
                pp: &PublicParams, 
                sk_s: ScalarField, 
                pk_c: Projective<g1config>,
                query: Query) -> Option<Response> {

    let verified = rep3_verify(&pp, pk_c, query.T, query.pi_c);
    if !verified {
        return None;
    }

    let s = ScalarField::rand(rng);
    let S = query.T.mul((sk_s+s).inverse().unwrap());

    let Y = pp.g2.mul(sk_s);
    let pi_s: DLEQProof = dleq_prove(rng, &pp, Y, S, query.T, s, sk_s);
    return Some(Response { s, S, pi_s });
}


fn rep3_prove(rng : &mut ThreadRng, 
        pp: &PublicParams, 
        X: Projective<g1config>, 
        T: Projective<g1config>,
        x: ScalarField,
        lambda: ScalarField, 
        r: ScalarField) -> REP3Proof {

    let a = ScalarField::rand(rng);
    let b = ScalarField::rand(rng);
    let c = ScalarField::rand(rng);
    
    
    let comm1 = pp.g1.mul(a);
    let comm2 = pp.g1.mul(a) + pp.g3.mul(b) + T.mul(c);
    let d = [pp.to_string(), X.to_string(), T.to_string(), comm1.to_string(), comm2.to_string()].concat();
    let ch = digest(d);
    let mut decoded = [0; 32];
    hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H1 Failed");
    let ch = ScalarField::from_be_bytes_mod_order(&decoded);

    let resp1 = a - ch*x;
    let resp2 = b - ch*r;
    let resp3 = c + ch*lambda.inverse().unwrap();

    return REP3Proof{ch, resp1, resp2, resp3}

}

fn rep3_verify(pp: &PublicParams, X: Projective<g1config>, T: Projective<g1config>, pi_c: REP3Proof) -> bool{

    let comm1_ = pp.g1.mul(pi_c.resp1) + X.mul(pi_c.ch);
    let comm2_ = pp.g1.mul(pi_c.resp1) + pp.g3.mul(pi_c.resp2) + T.mul(pi_c.resp3) - pp.g4.mul(pi_c.ch);
    
    let h = digest([pp.to_string(), X.to_string(), T.to_string(), comm1_.to_string(), comm2_.to_string()].concat());
    let mut decoded = [0; 32];
    hex::decode_to_slice(h, &mut decoded).expect("Decoding H1 Failed");
    let ch_ = ScalarField::from_be_bytes_mod_order(&decoded);
    
    return pi_c.ch == ch_;
}

fn dleq_prove(rng: &mut ThreadRng,
                pp: &PublicParams, 
                Y: Projective<g2config>,
                S: Projective<g1config>,
                T: Projective<g1config>,
                s: ScalarField,
                y: ScalarField) -> DLEQProof{

    let a = ScalarField::rand(rng);
    let comm1 = pp.g2.mul(a);
    let comm2 = S.mul(a);
    let ss = S.mul(s);
    let d = [pp.to_string(), Y.to_string(), S.to_string(), (T- ss).to_string(), comm1.to_string(), comm2.to_string()].concat();
    let ch = digest(d);
    let mut decoded = [0; 32];
    hex::decode_to_slice(ch, &mut decoded).expect("Decoding of H2 Failed");
    let ch = ScalarField::from_be_bytes_mod_order(&decoded);
    
    let resp = a  + ch*y;

    return DLEQProof {ch, resp}
}

fn dleq_verify(pp: &PublicParams, 
                Y: Projective<g2config>, 
                S: Projective<g1config>, 
                T: Projective<g1config>, 
                s: ScalarField,
                pi_s: DLEQProof) -> bool{

    let inter = T - S.mul(s);
    let comm1_ = pp.g2.mul(pi_s.resp) - Y.mul(pi_s.ch);
    let comm2_ = S.mul(pi_s.resp) - inter.mul(pi_s.ch);
    
    
    let h = digest([pp.to_string(), Y.to_string(), S.to_string(), inter.to_string(), comm1_.to_string(), comm2_.to_string()].concat());
    let mut decoded = [0; 32];
    hex::decode_to_slice(h, &mut decoded).expect("Decoding H2 Failed");
    let ch_ = ScalarField::from_be_bytes_mod_order(&decoded);

    return pi_s.ch == ch_;
}
// fn print_type_of<T>(_: &T) {
//     println!("{}", std::any::type_name::<T>())
// }
fn main() {
    let mut rng = ark_std::rand::thread_rng();
    let pp = setup(&mut rng);
    println!("G1: {:?}", pp.g1);
    println!("G2: {:?}", pp.g2);
    println!("G3: {:?}", pp.g3);
    println!("G4: {:?}", pp.g4);

    // Client KeyGen
    let sk_c = ScalarField::rand(&mut rng);
    let pk_c = pp.g1.mul(sk_c);

    // Server KeyGen
    let sk_s = ScalarField::rand(&mut rng);
    let pk_s = pp.g2.mul(sk_s);


    let rand_state = ScalarField::rand(&mut rng);
    let mut client = Client::new(&pp, pk_s, rand_state);
    let query = client.client_query(&mut rng, &pp, sk_c, pk_s);
    println!("Query: {:?}", query);
    

    let response = server_issue(&mut rng, &pp, sk_s, pk_c, query);

    match response {
        None => { panic!("Server Issue Failed"); }
        Some(resp) =>  { 
            
            println!("Received response: {:?}", resp); 
            let token = client.client_final(resp);
            match token {
                None => {panic!("Client Final Failed!");}
                Some(tok) => {println!("Received Token: {:?}", tok);}
            }
        } 
    };

    
}

