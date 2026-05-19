#![allow(non_snake_case)]

use super::ciphertext::Ciphertext;
use super::lagrange::Lagrange;
use super::params::Params;
use super::polynomial;
use super::private_key::PrivateKey;
use super::public_key::PublicKey;
use super::trapdoor::Trapdoor;

extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecdh;
use mcore::ed25519::ecp;
use mcore::rand::RAND;
use polynomial::Polynomial;
use rand::RngCore;
use std::time::Instant;

use log::error;
use mysql::prelude::*;
use mysql::*;
use rayon::prelude::*;
use serde_cbor;
use serde_json::json;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Generates a random seed for RNG
pub fn gen_seed() -> RAND {
    let mut rng = RAND::new();
    let mut seed = [0u8; 100];
    rand::thread_rng().fill_bytes(&mut seed);
    rng.clean();
    rng.seed(100, &seed);
    rng
}

/// KR-PAEKS Setup: Generates system parameters and the master secret key.
pub fn setup(params: &mut Params, k: usize) {
    let mut rng = gen_seed();
    let order = big::BIG::new_ints(&mcore::ed25519::rom::CURVE_ORDER);
    let msk = big::BIG::randomnum(&order, &mut rng);
    let g1 = ecp::ECP::generator();
    let g2 = g1.mul(&msk);

    //validate g1 and g2
    if is_valid(&g1) != 0 {
        println!("g1 is invalid! Abort!");
        std::process::abort();
    }

    if is_valid(&g2) != 0 {
        println!("g2 is invalid! Abort!");
        std::process::abort();
    }

    //Set the params
    params.set_params(g1, g2, msk, order, k);
}

/// Key Generation: Generates a public/private key pair.
pub fn keygen(params: &Params, pk: &mut PublicKey, sk: &mut PrivateKey) {
    let k = params.get_k();
    let order = params.get_order();
    let g1 = params.get_g1();
    let g2 = params.get_g2();

    let p1 = Polynomial::new_polynomial(k, *order);
    let p2 = Polynomial::new_polynomial(k, *order);

    let mut Dt = vec![ecp::ECP::new(); k];

    for i in 0..k {
        Dt[i] = g1.mul(&p1.get_coeff_at(i));
        Dt[i].add(&g2.mul(&p2.get_coeff_at(i)));
    }

    sk.set_private_key(p1, p2);
    pk.set_public_key(Dt);
}

/// Encrypts a keyword under the given public key.
pub fn encrypt(params: &Params, pk: &PublicKey, sk: &PrivateKey, keyword: &big::BIG) -> Ciphertext {
    let order = &params.order;
    let k = params.k;
    let mut rng = gen_seed();

    let mut hash_kw = keyword.clone();

    // Step 2: Generate random `r`
    let r = big::BIG::randomnum(order, &mut rng);

    // Step 3: Compute `temp = sk.p1.evaluate(hash_kw)`
    let temp = sk.p1.evaluate(&hash_kw);
    let newtemp = big::BIG::modmul(&temp, &r, order);

    // Step 4: Compute `C1`
    let mut c1 = pk.dt[0].mul(&hash_kw.powmod(&big::BIG::new_int(0), order));
    for i in 1..k {
        let exp = hash_kw.powmod(&big::BIG::new_int(i as isize), order);
        c1.add(&pk.dt[i].mul(&exp));
    }
    let tc1 = c1.mul(&newtemp); // Final `C1`

    // Step 5: Compute `temp2 = sk.p2.evaluate(hash_kw)`
    let temp2 = sk.p2.evaluate(&hash_kw);
    let newtemp2 = big::BIG::modmul(&temp2, &r, order);

    // Step 6: Compute `C2`
    let mut c2 = pk.dt[0].mul(&hash_kw.powmod(&big::BIG::new_int(0), order));
    for i in 1..k {
        let exp = hash_kw.powmod(&big::BIG::new_int(i as isize), order);
        c2.add(&pk.dt[i].mul(&exp));
    }
    let tc2 = c2.mul(&newtemp2); // Final `C2`

    // Step 7: Compute `u = p2(w) / p1(w) mod q`
    let mut u = sk.p2.evaluate(&hash_kw);
    let mut inv = sk.p1.evaluate(&hash_kw);
    inv.invmodp(order); // Compute modular inverse
    let new_u = big::BIG::modmul(&u, &inv, order);

    // Return the ciphertext
    Ciphertext::new_ciphertext(&tc1, &tc2, &new_u)
}

pub fn encrypt_multi_keyword(
    params: &Params,
    pk: &PublicKey,
    sk: &PrivateKey,
    keywords: &[String],
) -> Ciphertext {
    let order = &params.order;
    let k = params.k;
    let mut rng = gen_seed();

    // Generate a random r
    let r = big::BIG::randomnum(order, &mut rng);

    // Hash the keywords to a single BIG value
    let mut hash_kw = hash_to_big_array(keywords);

    // Compute temp = sk.p1.evaluate(hash_kw)
    let temp = sk.p1.evaluate(&hash_kw);
    let newtemp = big::BIG::modmul(&temp, &r, order);

    // Compute C1 using multi-keywords
    let mut c1 = pk.dt[0].mul(&hash_kw.powmod(&big::BIG::new_int(0), order));
    for i in 1..k {
        let exp = hash_kw.powmod(&big::BIG::new_int(i as isize), order);
        c1.add(&pk.dt[i].mul(&exp));
    }
    let tc1 = c1.mul(&newtemp); // Final C1

    // Compute temp2 = sk.p2.evaluate(hash_kw)
    let temp2 = sk.p2.evaluate(&hash_kw);
    let newtemp2 = big::BIG::modmul(&temp2, &r, order);

    // Compute C2 using multi-keywords
    let mut c2 = pk.dt[0].mul(&hash_kw.powmod(&big::BIG::new_int(0), order));
    for i in 1..k {
        let exp = hash_kw.powmod(&big::BIG::new_int(i as isize), order);
        c2.add(&pk.dt[i].mul(&exp));
    }
    let tc2 = c2.mul(&newtemp2); // Final C2

    // Compute u = p2(w) / p1(w) mod q
    let mut u = sk.p2.evaluate(&hash_kw);
    let mut inv = sk.p1.evaluate(&hash_kw);
    inv.invmodp(order); // Compute modular inverse
    let new_u = big::BIG::modmul(&u, &inv, order);

    Ciphertext::new_ciphertext(&tc1, &tc2, &new_u)
}

/// Generates a trapdoor for keyword search.
pub fn trapdoor(params: &Params, pk: &PublicKey, sk: &PrivateKey, keyword: &big::BIG) -> Trapdoor {
    let order = &params.order;
    let k = params.k;
    let mut rng = gen_seed();

    // Step 1: Compute `r`
    let r = big::BIG::randomnum(order, &mut rng);

    // Step 2: Compute `temp = sk.p1.evaluate(keyword)`
    let temp = sk.p1.evaluate(keyword);
    let newtemp = big::BIG::modmul(&temp, &r, order);

    // Step 3: Compute `T1`
    let mut t1 = ecp::ECP::new();
    for i in 0..k {
        let mut keyword_clone = keyword.clone(); // Clone keyword to allow mutation
        let exp = keyword_clone.powmod(&big::BIG::new_int(i as isize), order);
        let term = pk.dt[i].mul(&exp);
        t1.add(&term);
    }
    let tt1 = t1.mul(&newtemp); // TT1 = T1 * newtemp

    // Step 4: Compute `temp2 = sk.p2.evaluate(keyword)`
    let temp2 = sk.p2.evaluate(keyword);
    let newtemp2 = big::BIG::modmul(&temp2, &r, order);

    // Step 5: Compute `T2`
    let mut t2 = ecp::ECP::new();
    for i in 0..k {
        let mut keyword_clone = keyword.clone(); // Clone keyword to allow mutation
        let exp = keyword_clone.powmod(&big::BIG::new_int(i as isize), order);
        let term = pk.dt[i].mul(&exp);
        t2.add(&term);
    }
    let tt2 = t2.mul(&newtemp2); // TT2 = T2 * newtemp2

    // Step 6: Compute `u_cap`
    let mut u_cap = sk.p2.evaluate(keyword);
    let mut inv = sk.p1.evaluate(keyword).clone(); // Clone before inverting
    inv.invmodp(order); // Now modify `inv` safely
    let new_u_cap = big::BIG::modmul(&u_cap, &inv, order);

    Trapdoor::new_trapdoor(&tt1, &tt2, &new_u_cap)
}

pub fn trapdoor_multi_keyword(
    params: &Params,
    pk: &PublicKey,
    sk: &PrivateKey,
    keywords: &[String],
) -> Trapdoor {
    let order = &params.order;
    let k = params.k;
    let mut rng = gen_seed();

    // Generate random r
    let r = big::BIG::randomnum(order, &mut rng);

    // Hash the keywords to a single BIG value
    let mut hash_kw = hash_to_big_array(keywords);

    // Compute temp = sk.p1.evaluate(hash_kw)
    let temp = sk.p1.evaluate(&hash_kw);
    let newtemp = big::BIG::modmul(&temp, &r, order);

    // Compute T1 using multi-keywords
    let mut t1 = ecp::ECP::new();
    for i in 0..k {
        let mut keyword_clone = hash_kw.clone();
        let exp = keyword_clone.powmod(&big::BIG::new_int(i as isize), order);
        let term = pk.dt[i].mul(&exp);
        t1.add(&term);
    }
    let tt1 = t1.mul(&newtemp); // TT1 = T1 * newtemp

    // Compute temp2 = sk.p2.evaluate(hash_kw)
    let temp2 = sk.p2.evaluate(&hash_kw);
    let newtemp2 = big::BIG::modmul(&temp2, &r, order);

    // Compute T2 using multi-keywords
    let mut t2 = ecp::ECP::new();
    for i in 0..k {
        let mut keyword_clone = hash_kw.clone();
        let exp = keyword_clone.powmod(&big::BIG::new_int(i as isize), order);
        let term = pk.dt[i].mul(&exp);
        t2.add(&term);
    }
    let tt2 = t2.mul(&newtemp2); // TT2 = T2 * newtemp2

    // Compute u_cap
    let mut u_cap = sk.p2.evaluate(&hash_kw);
    let mut inv = sk.p1.evaluate(&hash_kw).clone(); // Clone before inverting
    inv.invmodp(order); // Now modify inv safely
    let new_u_cap = big::BIG::modmul(&u_cap, &inv, order);

    Trapdoor::new_trapdoor(&tt1, &tt2, &new_u_cap)
}

/// Tests if a ciphertext contains the keyword using the trapdoor.

pub fn test(ciphertext: &Ciphertext, trapdoor: &Trapdoor) -> bool {
    // Compute LHS: u * C1 + T2
    let mut lhs = ciphertext.c1.mul(&ciphertext.u);
    lhs.add(&trapdoor.t2);

    // Compute RHS: u_cap * T1 + C2
    let mut rhs = trapdoor.t1.mul(&trapdoor.u_cap);
    rhs.add(&ciphertext.c2);

    // Check if LHS equals RHS
    lhs.equals(&rhs)
}

/// Main function: Runs the full KR-PAEKS scheme
fn main() {
    let k = 20;

    let keyword_str = "secure";
    let keyword = hash_to_big(keyword_str);

    let mut params = Params::new();

    let mut sender_pk = PublicKey::new();
    let mut sender_sk = PrivateKey::new();

    let mut receiver_pk = PublicKey::new();
    let mut receiver_sk = PrivateKey::new();

    println!("======== Running KR-PAEKS ========");

    // Setup
    let setup_start = Instant::now();
    setup(&mut params, k);
    let setup_time = setup_start.elapsed();
    params.print();

    // Sender Key Generation
    let sender_keygen_start = Instant::now();
    keygen(&params, &mut sender_pk, &mut sender_sk);
    let sender_keygen_time = sender_keygen_start.elapsed();

    println!("\n======== Begin Sender ========\n");
    sender_sk.print();
    sender_pk.print();
    println!("\n======== End Sender ========\n");

    // Receiver Key Generation
    let receiver_keygen_start = Instant::now();
    keygen(&params, &mut receiver_pk, &mut receiver_sk);
    let receiver_keygen_time = receiver_keygen_start.elapsed();

    println!("\n======== Begin Receiver ========\n");
    receiver_sk.print();
    receiver_pk.print();
    println!("\n======== End Receiver ========\n");

    // Encrypt
    let ciphertext_start = Instant::now();
    let ciphertext = encrypt(&params, &receiver_pk, &sender_sk, &keyword);
    let ciphertext_time = ciphertext_start.elapsed();
    ciphertext.print();

    // Generate Trapdoor
    let trapdoor_start = Instant::now();
    let trapdoor1 = trapdoor(&params, &sender_pk, &receiver_sk, &keyword);
    let trapdoor_time = trapdoor_start.elapsed();
    trapdoor1.print();

    // Test
    let test_start = Instant::now();
    let test_result = test(&ciphertext, &trapdoor1);
    let test_time = test_start.elapsed();

    // if test_result {
    //     println!("Test Successful!\n");
    //     println!("====== Runtime ======\nSetup Time = {:?}\nSender KeyGen Time = {:?}\nReceiver KeyGen Time = {:?}\nCiphertext Time = {:?}\nTrapdoor Time = {:?}\nTest Time = {:?}",
    //                 setup_time, sender_keygen_time, receiver_keygen_time, ciphertext_time, trapdoor_time, test_time);
    //     println!("====================");
    // } else {
    //     println!("Test Unsuccessful!");
    // }

    // let url = "mysql://root:root@192.168.68.110/EnronMailDS";
    // let pool = Pool::new(url)?;

    // // test_sql_enc(&params, &receiver_pk, &sender_sk, "Forwarded", &pool).unwrap();

    // // let keyword_test = "Forwarded";
    // // let kw = hash_to_big(keyword_test);
    // // let trapdoor_start = Instant::now();
    // // let testt = trapdoor(&params, &sender_pk, &receiver_sk, &kw);
    // // let trapdoor_time = trapdoor_start.elapsed().as_millis();
    // // println!("\nTime for Generating Trapdoor with k={}: {} ms.\n", params.get_k(), trapdoor_time);

    // let kw1: &[String] = &vec!["forwarded".to_string(), "please".to_string(), "hey".to_string()];
    // test_sql_enc_multi(&params, &receiver_pk, &sender_sk, kw1, &pool).unwrap();

    // // let kw = hash_to_big_array(kw1);
    // let trapdoor_start = Instant::now();
    // let testt = trapdoor_multi_keyword(&params, &sender_pk, &receiver_sk, &kw1);
    // let trapdoor_time = trapdoor_start.elapsed().as_millis();
    // println!("\nTime for Generating Trapdoor with k={}: {} ms.\n", params.get_k(), trapdoor_time);

    // test_sql_test(&params, &testt, &pool).unwrap();

    // Ok(())
}

/// Converts a string to a `BIG` using SHAKE256.
pub fn hash_to_big(input: &str) -> big::BIG {
    use mcore::sha3::{SHA3, SHAKE256};

    let mut hasher = SHA3::new(SHAKE256);
    hasher.process_array(input.as_bytes());

    let mut output = [0u8; big::MODBYTES];
    hasher.shake(&mut output, big::MODBYTES);

    big::BIG::frombytes(&output)
}

fn hash_to_big_array(keywords: &[String]) -> big::BIG {
    let mut combined_str = String::new();
    for keyword in keywords {
        combined_str.push_str(keyword);
    }

    use mcore::sha3::{SHA3, SHAKE256};

    let mut hasher = SHA3::new(SHAKE256);
    hasher.process_array(combined_str.as_bytes());

    let mut output = [0u8; big::MODBYTES];
    hasher.shake(&mut output, big::MODBYTES);

    big::BIG::frombytes(&output)
}

fn is_valid(p: &ecp::ECP) -> isize {
    let mut bytes = vec![0; big::MODBYTES + 1];
    p.tobytes(&mut bytes, true);

    let result = ecdh::public_key_validate(&bytes);
    if result != 0 {
        return result;
    }
    0
}

// pub fn test_sql_enc(
//     params: &Params,
//     rpk: &PublicKey,
//     ssk: &PrivateKey,
//     kw: &str,
//     pool: &Pool,  // Pass a pre-initialized connection pool
// ) -> std::result::Result<(), Box<dyn Error>> {
//     let mut conn = pool.get_conn()?;
//     let query = "SELECT IdEmail, body, Date, `X-To` FROM JohnArnoldMail";
//     let emails: Vec<(i32, Option<String>, String, String)> = conn.query(query)?;

//     let total_enc_time = AtomicU64::new(0);
//     let cnt = AtomicU64::new(0);
//     let keyword = hash_to_big(kw);

//     // Use par_iter() instead of into_par_iter()
//     let encrypted_results: Vec<(String, String, String, i32)> = emails
//         .par_iter()
//         .filter_map(|(id, body, date, to)| {
//             if let Some(body) = body {
//                 if body.contains(kw) {
//                     let start = Instant::now();
//                     let ciphertext = encrypt(params, rpk, ssk, &keyword);
//                     let elapsed = start.elapsed().as_millis() as u64;

//                     total_enc_time.fetch_add(elapsed, Ordering::SeqCst);
//                     cnt.fetch_add(1, Ordering::SeqCst);

//                     let string_cipher = serde_cbor::to_vec(&ciphertext).ok()?; // Use CBOR instead of JSON
//                     let encoded_cipher = base64::encode(&string_cipher);
//                     return Some((encoded_cipher, date.clone(), to.clone(), *id));
//                 }
//             }
//             None
//         })
//         .collect();

//     // Batch update with prepared statements
//     if !encrypted_results.is_empty() {
//         let mut stmt = conn.prep("UPDATE JohnArnoldMail SET ciphertext = ? WHERE `Date` = ? AND `X-To` = ? AND `IdEmail` = ?")?;
//         conn.exec_batch(&stmt, encrypted_results)?;
//     }

//     let total_time = total_enc_time.load(Ordering::SeqCst);
//     let count = cnt.load(Ordering::SeqCst);

//     println!("\nTotal Number of Emails Encrypted: {}\n", count);
//     println!("Total Time Encrypting {} Emails: {} ms.\n", count, total_time);
//     if count > 0 {
//         println!("Average Time Encrypting 1 Email: {} ms.\n", total_time / count);
//     }

//     Ok(())
// }

// pub fn test_sql_enc_multi(
//     params: &Params,
//     rpk: &PublicKey,
//     ssk: &PrivateKey,
//     kw: &[String],
//     pool: &Pool,  // Pass a pre-initialized connection pool
// ) -> std::result::Result<(), Box<dyn Error>> {
//     let mut conn = pool.get_conn()?;
//     let query = "SELECT IdEmail, body, Date, `X-To` FROM JohnArnoldMail";
//     let emails: Vec<(i32, Option<String>, String, String)> = conn.query(query)?;

//     let total_enc_time = AtomicU64::new(0);
//     let cnt = AtomicU64::new(0);
//     let keyword = hash_to_big_array(kw);

//     // Use par_iter() instead of into_par_iter()
//     let encrypted_results: Vec<(String, String, String, i32)> = emails
//     .par_iter()
//     .filter_map(|(id, body, date, to)| {
//         if let Some(body) = body {
//             let mut ccontains_all_keywords = true;
//             let body_lower = body.to_lowercase();

//             // Check if body contains all keywords
//             for keyword in kw {
//                 if !body_lower.contains(&keyword.to_lowercase()) {
//                     ccontains_all_keywords = false;
//                     break;
//                 }
//             }

//             if ccontains_all_keywords {
//                 let start = Instant::now();
//                 let ciphertext = encrypt_multi_keyword(params, rpk, ssk, &kw);  // Assuming kw is the list of keywords
//                 let elapsed = start.elapsed().as_millis() as u64;

//                 // Accumulate encryption time and count
//                 total_enc_time.fetch_add(elapsed, Ordering::SeqCst);
//                 cnt.fetch_add(1, Ordering::SeqCst);

//                 // Serialize ciphertext using CBOR and encode it in base64
//                 let string_cipher = serde_cbor::to_vec(&ciphertext).ok()?;
//                 let encoded_cipher = base64::encode(&string_cipher);

//                 // Return the result as a tuple
//                 return Some((encoded_cipher, date.clone(), to.clone(), *id));
//             }
//         }
//         None
//     })
//     .collect();

//     // Batch update with prepared statements
//     if !encrypted_results.is_empty() {
//         let mut stmt = conn.prep("UPDATE JohnArnoldMail SET ciphertext = ? WHERE `Date` = ? AND `X-To` = ? AND `IdEmail` = ?")?;
//         conn.exec_batch(&stmt, encrypted_results)?;
//     }

//     let total_time = total_enc_time.load(Ordering::SeqCst);
//     let count = cnt.load(Ordering::SeqCst);

//     println!("\nTotal Number of Emails Encrypted: {}\n", count);
//     println!("Total Time Encrypting {} Emails: {} ms.\n", count, total_time);
//     if count > 0 {
//         println!("Average Time Encrypting 1 Email: {} ms.\n", total_time / count);
//     }

//     Ok(())
// }

// pub fn test_sql_test(params: &Params, t: &Trapdoor, pool: &Pool) -> std::result::Result<(), Box<dyn Error>> {
//     let mut conn = pool.get_conn()?;
//     let query = "SELECT ciphertext, Date, `X-To` FROM JohnArnoldMail WHERE ciphertext IS NOT NULL";
//     let emails: Vec<(Option<String>, String, String)> = conn.query(query)?;

//     let total_test_time = AtomicU64::new(0);
//     let cnt = AtomicU64::new(0);
//     // let keyword = hash_to_big(kw);

//     let matched_results: Vec<(String, String)> = emails
//         .par_iter()
//         .filter_map(|(ciphertext_opt, date, to)| {
//             if let Some(ciphertext_base64) = ciphertext_opt {
//                 // Decode base64 & CBOR
//                 let decoded_ciphertext = base64::decode(ciphertext_base64).ok()?;
//                 let ciphertext: Ciphertext = serde_cbor::from_slice(&decoded_ciphertext).ok()?;

//                 let start = Instant::now();
//                 let result =  test(&ciphertext, t);
//                 let elapsed = start.elapsed().as_millis() as u64;
//                 total_test_time.fetch_add(elapsed, Ordering::SeqCst);
//                 cnt.fetch_add(1, Ordering::SeqCst);

//                 if result {
//                     return Some((date.clone(), to.clone()));
//                 }
//             }
//             None
//         })
//         .collect();

//     println!("\nTotal Number of Emails Matched: {}\n", cnt.load(Ordering::SeqCst));
//     println!("Total Time Testing {} Emails: {} ms.\n", cnt.load(Ordering::SeqCst), total_test_time.load(Ordering::SeqCst));

//     Ok(())
// }
