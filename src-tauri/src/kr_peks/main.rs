#![allow(non_snake_case)]

use super::ciphertext::Ciphertext;
use super::params::Params;
use super::polynomial::Polynomial;
use super::private_key::PrivateKey;
use super::public_key::PublicKey;
use super::trapdoor::Trapdoor;
use super::utils::*;

use base64::*;
use mcore::ed25519::big;
use mcore::ed25519::ecp;
use mcore::ed25519::rom;
use mysql::prelude::*;
use mysql::*;
use serde_json::{json, Value};
use std::env;
use std::time::Instant;

pub fn setup(params: &mut Params, k: usize) {
    let order = big::BIG::new_ints(&rom::CURVE_ORDER);

    let mut rng = gen_seed();
    let r = big::BIG::randomnum(&order, &mut rng);

    let g1 = ecp::ECP::generator();
    let g2 = g1.mul(&r);

    params.set_params(k, order, g1, g2);
}

pub fn keygen(params: &Params, pk: &mut PublicKey, sk: &mut PrivateKey) {
    let k = params.get_k() + 1;
    let order = params.get_order();
    let g1 = params.get_g1();
    let g2 = params.get_g2();

    let p1 = Polynomial::new_polynomial(k, *order);
    let p2 = Polynomial::new_polynomial(k, *order);

    let mut Dt = vec![ecp::ECP::new(); k];

    for i in 0..k {
        Dt[i] = g1.mul(&p1.get_coeff_i(i));
        Dt[i].add(&g2.mul(&p2.get_coeff_i(i)));
    }

    sk.set_private_key(p1, p2);
    pk.set_public_key(Dt);
}

pub fn peks(params: &Params, pk: &PublicKey, w: &Vec<u8>) -> Option<Ciphertext> {
    if pk.is_valid() != 0 {
        println!("Public Key is invalid!");
        return None;
    }

    let k = params.get_k() + 1;
    let order = params.get_order();
    let g1 = params.get_g1();
    let g2 = params.get_g2();

    let mut hashw = hash_to_big(w, order);
    // println!("Hash of '{}': {}", w, big_to_hex(&hashw));

    let mut rng = gen_seed();
    let r = big::BIG::randomnum(&order, &mut rng);

    let u1 = g1.mul(&r);
    let u2 = g2.mul(&r);

    let mut sw = pk
        .get_Dt_i(0)
        .mul(&big::BIG::powmod(&mut hashw, &big::BIG::new_int(0), &order));
    for i in 1..k {
        let i_isize: isize = i.try_into().unwrap();
        sw.add(&pk.get_Dt_i(i).mul(&big::BIG::powmod(
            &mut hashw,
            &big::BIG::new_int(i_isize),
            &order,
        )));
    }
    sw = sw.mul(&r);

    Some(Ciphertext::new_ciphertext(&u1, &u2, &sw))
}

pub fn trapdoor(params: &Params, sk: &PrivateKey, w: &Vec<u8>) -> Trapdoor {
    let order = params.get_order();
    let hashw = hash_to_big(w, order);

    let p1 = sk.get_p1().evaluate(hashw);
    let p2 = sk.get_p2().evaluate(hashw);

    Trapdoor::new_trapdoor(&p1, &p2)
}

pub fn test(c: &Ciphertext, t: &Trapdoor) -> bool {
    let mut right = c.get_u1().mul(&t.get_p1());
    right.add(&c.get_u2().mul(&t.get_p2()));

    if c.get_sw().equals(&right) {
        true
    } else {
        false
    }
}

fn main() {
    let w = "urgent";
    let k = 20;
    // Convert strings to byte arrays
    let w_bytes = string_to_bytes(w);

    let mut params = Params::new();
    let mut pk = PublicKey::new();
    let mut sk = PrivateKey::new();
    let mut c = Ciphertext::new();

    // User import params, sk, pk, ciphertext from files: cargo run parameter.params privatekey.sk publickey.pk ciphertext.cipher
    let args: Vec<String> = env::args().collect();
    for i in &args {
        if i.contains(".params") {
            let result = import_params(&mut params, &i);
            match result {
                Ok(_) => {
                    if params.is_valid() {
                        println!("System parameters imported successfully!");
                    } else {
                        eprintln!(
                            "Failed to import system parameters: System parameters are invalid."
                        );
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to import system parameters: {}", e);
                    return;
                }
            }
        } else if i.contains(".sk") {
            let result = import_sk(&mut sk, &i);
            match result {
                Ok(_) => {
                    if sk.is_valid() {
                        println!("Private key imported successfully!");
                    } else {
                        eprintln!("Failed to import private key: Private key is invalid.");
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to import private key: {}", e);
                    return;
                }
            }
        } else if i.contains(".pk") {
            let result = import_pk(&mut pk, &i);
            match result {
                Ok(_) => {
                    if pk.is_valid() == 0 {
                        println!("Public key imported successfully!");
                    } else {
                        eprintln!("Failed to import public key: Public key is invalid.");
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to import public key: {}", e);
                    return;
                }
            }
        } else if i.contains(".cipher") {
            let result = import_c(&mut c, &i);
            match result {
                Ok(_) => {
                    if c.is_valid() {
                        println!("Ciphertext imported successfully!");
                    } else {
                        eprintln!("Failed to import ciphertext: Ciphertext is invalid.");
                        return;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to import ciphertext: {}", e);
                    return;
                }
            }
        }
    }

    // No import from file
    if *&args.len() <= 1 {
        let start = Instant::now();
        setup(&mut params, k);
        let duration = start.elapsed();
        println!("Setup took: {:?}", duration);

        let start = Instant::now();
        keygen(&params, &mut pk, &mut sk);
        let duration = start.elapsed();
        println!("Keygen took: {:?}", duration);

        let start = Instant::now();
        c = match peks(&params, &pk, &w_bytes) {
            Some(ciphertext) => ciphertext,
            None => return,
        };
        let duration = start.elapsed();
        println!("PEKS took: {:?}", duration);

        export_params(&params, "parameter.params");
        export_sk(&sk, "privatekey.sk");
        export_c(&c, "ciphertext.cipher");

        match export_pk(&pk, "publickey.pk") {
            Ok(_) => (),
            Err(e) => println!("{}", e),
        }
        let duration = start.elapsed();
    }

    params.print();

    sk.print();
    pk.print();

    c.print();

    let start = Instant::now();
    let t = trapdoor(&params, &sk, &w_bytes);
    t.print();
    let duration = start.elapsed();
    println!("Trapdoor took: {:?}", duration);

    let start = Instant::now();
    let result = test(&c, &t);
    let duration = start.elapsed();

    if result {
        println!("\nTest Successful!");
        println!("Test took: {:?}", duration);
    } else {
        println!("\nTest Unsuccessful!");
    }

    //****************Performance Analysis****************
    // let TestCiphertextTime = Instant::now();
    // TestSQLEnc(&params, &pk, "Forwarded");
    // let FinalTestCiphertextTime = TestCiphertextTime.elapsed();

    // let TestTrapdoorTime = Instant::now();
    // let trapdoor_test = trapdoor(&params, &sk, "Forwarded");
    // let FinalTestTrapdoorTime = TestTrapdoorTime.elapsed();

    // let SqlTestTime = Instant::now();
    // let SqlTestCnt = TestSQLTest(&trapdoor_test);
    // let FinalSqlTestTime = SqlTestTime.elapsed();

    // println!("\nTotal Number of Test: {}", SqlTestCnt);
    // println!("===========Runtime===========");
    // println!("Time for Encrypt All Emails Contain Keyword \"Forwarded\": {} ms", FinalTestCiphertextTime.as_millis());
    // println!("Time for Gen Trapdoor: {} ms", FinalTestTrapdoorTime.as_millis());
    // println!("Time for Test All Ciphertext: {} ms", FinalSqlTestTime.as_millis());
    // println!("===========End Runtime===========");

    // Calculate average time
    // let mut times = Vec::new();

    // for i in 0..100 {
    //     let overall_start = Instant::now();

    //     let w = "Urgent";

    //     let mut params = Params::new();
    //     let mut pk = PublicKey::new();
    //     let mut sk = PrivateKey::new();

    //     let setup_start = Instant::now();
    //     setup(&mut params);
    //     let setup_time = setup_start.elapsed();
    //     // params.print();

    //     let keygen_start = Instant::now();
    //     keygen(&params, &mut pk, &mut sk);
    //     let keygen_time = keygen_start.elapsed();
    //     // sk.print();
    //     // pk.print();

    //     let peks_start = Instant::now();
    //     let c = peks(&params, &pk, &w);
    //     let peks_time = peks_start.elapsed();
    //     // c.print();

    //     let trapdoor_start = Instant::now();
    //     let t = trapdoor(&params, &sk, &w);
    //     let trapdoor_time = trapdoor_start.elapsed();
    //     // t.print();

    //     let test_start = Instant::now();
    //     let result = test(&c, &t);
    //     let test_time = test_start.elapsed();

    //     let total_time = overall_start.elapsed();

    //     times.push(vec![
    //         setup_time.as_secs_f64() * 1000.0,
    //         keygen_time.as_secs_f64() * 1000.0,
    //         peks_time.as_secs_f64() * 1000.0,
    //         trapdoor_time.as_secs_f64() * 1000.0,
    //         test_time.as_secs_f64() * 1000.0,
    //         total_time.as_secs_f64() * 1000.0,
    //     ]);

    //     if result {
    //         println!("Test Successful!");
    //     } else {
    //         println!("Test Unsuccessful!");
    //     }

    //     // println!("{} - Setup Time: {:.2?}, Keygen Time: {:.2?}, PEKS Time: {:.2?}, Trapdoor Time: {:.2?}, Test Time: {:.2?}, Total Time: {:.2?}", i, setup_time, keygen_time, peks_time, trapdoor_time, test_time, total_time);
    // }

    // let avg_times: Vec<f64> = (0..6).map(|i| {
    //     times.iter().map(|t| t[i]).sum::<f64>() / times.len() as f64
    // }).collect();

    // println!("\nAverage Times:");
    // println!("Setup Time: {:.2} ms", avg_times[0]);
    // println!("Keygen Time: {:.2} ms", avg_times[1]);
    // println!("PEKS Time: {:.2} ms", avg_times[2]);
    // println!("Trapdoor Time: {:.2} ms", avg_times[3]);
    // println!("Test Time: {:.2} ms", avg_times[4]);
    // println!("Total Time: {:.2} ms", avg_times[5]);

    //****************End Performance Analysis****************
}

fn TestSQLEnc(params: &Params, pk: &PublicKey, w: &Vec<u8>) {
    let url = "mysql://root@127.0.0.1/EnronMailDS";
    let pool = Pool::new(url).expect("Failed to create pool.");
    let mut conn = pool.get_conn().expect("Failed to get connection.");

    let select_stmt = "SELECT `body`, `Date`, `X-To` FROM JohnArnoldMail";
    let result: Vec<Row> = conn.query(select_stmt).expect("Query failed.");

    for row in result {
        let body: Option<String> = row.get("body");
        let date: String = row.get("Date").unwrap();
        let to: String = row.get("X-To").unwrap();

        if let Some(body) = body {
            // Convert the body string to a byte vector
            let body_bytes = body.as_bytes();

            // Check if the byte vector `w` is contained in `body_bytes`
            if body_bytes.windows(w.len()).any(|window| window == w) {
                let ciphertext = match peks(&params, &pk, &w) {
                    Some(ciphertext) => ciphertext,
                    None => return,
                };

                let StringCipher = json!({
                    "u1": encode(ecp_to_bytes(ciphertext.get_u1())),
                    "u2": encode(ecp_to_bytes(ciphertext.get_u2())),
                    "sw": encode(ecp_to_bytes(ciphertext.get_sw()))
                });

                let update_stmt =
                    "UPDATE JohnArnoldMail SET ciphertext = ? WHERE `Date` = ? AND `X-To` = ?";
                conn.exec_drop(update_stmt, (StringCipher, date, to))
                    .expect("Update failed.");
            }
        }
    }
}

fn TestSQLTest(t: &Trapdoor) -> i32 {
    let url = "mysql://root@127.0.0.1/EnronMailDS";
    let pool = Pool::new(url).expect("Failed to create pool.");
    let mut conn = pool.get_conn().expect("Failed to get connection.");

    let select_stmt = "SELECT ciphertext FROM JohnArnoldMail";
    let result: Vec<Row> = conn.query(select_stmt).expect("Query failed.");

    let mut cnt = 1;

    for row in result {
        let ciphertext_opt: Option<Option<String>> = row
            .get_opt("ciphertext")
            .expect("Failed to retrieve ciphertext_opt.")
            .ok();

        if let Some(Some(ciphertext_string)) = ciphertext_opt {
            let data: Value = serde_json::from_str(&ciphertext_string)
                .expect("Failed to deserialize ciphertext.");

            let u1 = bytes_to_ecp(
                &decode(
                    data["u1"]
                        .as_str()
                        .expect("Failed to get a valid string from JSON"),
                )
                .expect("Failed to decode base64"),
            );
            let u2 = bytes_to_ecp(
                &decode(
                    data["u2"]
                        .as_str()
                        .expect("Failed to get a valid string from JSON"),
                )
                .expect("Failed to decode base64"),
            );
            let sw = bytes_to_ecp(
                &decode(
                    data["sw"]
                        .as_str()
                        .expect("Failed to get a valid string from JSON"),
                )
                .expect("Failed to decode base64"),
            );

            let c = Ciphertext::new_ciphertext(&u1, &u2, &sw);

            let CntTest = test(&c, &t);
            if CntTest {
                cnt += 1;
            }
        }
    }
    cnt
}
