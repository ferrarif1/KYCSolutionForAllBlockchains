extern crate core;
use core::bls12381::big::BIG;
use core::rand::RAND;

use core::bls12381::ecp::ECP;
use core::bls12381::ecp2::ECP2;
use core::bls12381::rom;

pub mod bbs_plus;
pub mod cl;
pub mod ps;

use bbs_plus::signature::{BBSPlusKey, BBSPlusPublicKey, BBSPlusSig};
use ps::signature::{key_generation, SecretKey, Signature};

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::sync::mpsc;



fn main() {
    
    // Extract order of curve
    let mut q = BIG::new_ints(&rom::CURVE_ORDER);
    //
    let attributes = vec!["name=alice", "age=122", "address=X"];
    //
    // Needs to be actually random
    let mut raw2: [u8; 50] = [0; 50];
    let mut rng2 = RAND::new();
    rng2.clean();
    for i in 0..50 {
        raw2[i] = i as u8
    }
    rng2.seed(50, &raw2);

    println!("BBS+ Signature");
    println!("Key Gen");
    let bbs_plus_key = BBSPlusKey::new(attributes.len(), &q, &mut rng2);

    println!("Sign");
    let signature = bbs_plus_key.sign(attributes, &q, &mut rng2);

    let test = vec!["name=alice", "age=122", "address=X"];

    println!("Verify");
    let verified = signature.verify(test, &bbs_plus_key.pk, &q);

    println!("attributes == test, Should be true, Verified : {} ", verified);

    let test2 = vec!["name", "dob", "address"];

    println!("PS Signature");
    println!("Key Gen");
    let (ps_pk, ps_sk) = key_generation(test2.len(), &q, &mut rng2);

    println!("Sign");
    let ps_signature = Signature::new(test2, &ps_sk, &q, &mut rng2);

    let test3 = vec!["name", "dob", "address"];

    println!("Verify");
    let ps_verified = ps_pk.verify(&ps_signature, test3, &q, &mut rng2);

    println!("test2 == test3, Should be true,Verified : {} ", ps_verified);
}
