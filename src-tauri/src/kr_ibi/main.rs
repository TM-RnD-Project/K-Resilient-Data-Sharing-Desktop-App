#![allow(non_snake_case)]

use super::params::Params;
use std::time::Instant;

extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;
use mcore::ed25519::rom;
use mcore::rand::RAND;
use mcore::sha3::{SHA3, SHAKE256};
use rand::rngs::OsRng;
use rand::RngCore;

use mcore::ed25519::big::BIG;
use mcore::ed25519::ecp::ECP;

pub fn setup(params: &mut Params, k: usize) {
    let start = Instant::now();

    let order = big::BIG::new_ints(&rom::CURVE_ORDER);

    let g = ecp::ECP::generator();

    let mut rng = gen_seed();
    let t = k + 1;

    let mut fx1 = vec![big::BIG::new(); t];
    let mut fx2 = vec![big::BIG::new(); t];

    for i in 0..t {
        fx1[i] = big::BIG::randomnum(&order, &mut rng);
        fx2[i] = big::BIG::randomnum(&order, &mut rng);
    }

    let mut Dt1 = vec![ecp::ECP::new(); t];
    let mut Dt2 = vec![ecp::ECP::new(); t];

    for i in 0..t {
        Dt1[i] = g.mul(&fx1[i]);
        Dt2[i] = g.mul(&fx2[i]);
    }

    params.set_params(k, order, g, Dt1, Dt2, fx1, fx2);
    println!("Setup time: {:?}", start.elapsed());
}

pub fn extract(params: &Params, id: &[u8]) -> (big::BIG, big::BIG) {
    let start = Instant::now();
    let k = params.get_k() + 1;
    let order = params.get_order();
    let d1 = params.get_msk1();
    let d2 = params.get_msk2();

    let mut x = hash_to_big(id);

    let mut f1 = big::BIG::new_int(0);
    let mut f2 = big::BIG::new_int(0);

    for i in 0..k {
        let i_isize: isize = i.try_into().unwrap();
        let xpowi = big::BIG::powmod(&mut x, &big::BIG::new_int(i_isize), &order);

        let temp1 = big::BIG::modmul(&d1[i], &xpowi, &order);
        f1.add(&temp1);
        f1.rmod(&order);

        let temp2 = big::BIG::modmul(&d2[i], &xpowi, &order);
        f2.add(&temp2);
        f2.rmod(&order);
    }

    println!("Extract time: {:?}", start.elapsed());
    (f1, f2)
}

// Prover Commitment
pub fn commit(params: &Params, rng: &mut RAND) -> ((ecp::ECP, ecp::ECP), (big::BIG, big::BIG)) {
    let r1 = big::BIG::randomnum(params.get_order(), rng);
    let r2 = big::BIG::randomnum(params.get_order(), rng);

    let g_r1 = params.get_g().mul(&r1);
    let g_r2 = params.get_g().mul(&r2);

    ((g_r1, g_r2), (r1, r2))
}

// Verifier's Challenge
pub fn challenge(params: &Params, rng: &mut RAND) -> (big::BIG, big::BIG) {
    let c1 = big::BIG::randomnum(params.get_order(), rng);
    let c2 = big::BIG::randomnum(params.get_order(), rng);

    (c1, c2)
}

// Prover's Response
pub fn respond(
    r: &(big::BIG, big::BIG),
    challenge: &(big::BIG, big::BIG),
    f_id: &(big::BIG, big::BIG),
    order: &big::BIG,
) -> (big::BIG, big::BIG) {
    let mut response_1 = big::BIG::modmul(&f_id.0, &challenge.0, order);
    response_1 = big::BIG::modadd(&response_1, &r.0, order);

    let mut response_2 = big::BIG::modmul(&f_id.1, &challenge.1, order);
    response_2 = big::BIG::modadd(&response_2, &r.1, order);

    (response_1, response_2)
}

pub fn verify(
    params: &Params,
    g_r: &(ecp::ECP, ecp::ECP),
    response: &(big::BIG, big::BIG),
    challenge: &(big::BIG, big::BIG),
    id: &[u8],
) -> bool {
    let start = Instant::now();
    let mut x = hash_to_big(id);

    let f_id_point1 = {
        let mut sum = ecp::ECP::new();
        for i in 0..params.get_k() + 1 {
            let i_isize = big::BIG::new_int(i as isize);
            let xpowi = big::BIG::powmod(&mut x, &i_isize, params.get_order());
            let temp = params.get_Dt1()[i].mul(&xpowi);
            sum.add(&temp);
        }
        sum
    };

    let f_id_point2 = {
        let mut sum = ecp::ECP::new();
        for i in 0..params.get_k() + 1 {
            let i_isize = big::BIG::new_int(i as isize);
            let xpowi = big::BIG::powmod(&mut x, &i_isize, params.get_order());
            let temp = params.get_Dt2()[i].mul(&xpowi);
            sum.add(&temp);
        }
        sum
    };

    for i in 0..params.get_k() + 1 {
        let public_key_1: &ecp::ECP = &params.get_Dt1()[i];
        let public_key_2: &ecp::ECP = &params.get_Dt2()[i];

        if public_key_1.is_infinity() || public_key_2.is_infinity() {
            println!("Invalid public key at index {}", i);
            return false;
        }
    }

    let mut g_r_f_id_c1 = f_id_point1.mul(&challenge.0);
    g_r_f_id_c1.add(&g_r.0);

    let mut g_r_f_id_c2 = f_id_point2.mul(&challenge.1);
    g_r_f_id_c2.add(&g_r.1);

    let valid_1 = g_r_f_id_c1.equals(&ecp::ECP::generator().mul(&response.0));
    let valid_2 = g_r_f_id_c2.equals(&ecp::ECP::generator().mul(&response.1));

    if !valid_1 || !valid_2 {
        println!("Commitment or response verification failed.");
    }
    let duration = start.elapsed(); // Calculate the elapsed time
    println!("Verification time: {:?}", duration); // Output the timing information
    valid_1 && valid_2
}

fn main() {
    let start_total = Instant::now();
    let id: &str = "aniksen360@mail.com";
    let k = 20;
    let id = string_to_bytes(id);

    let mut params: Params = Params::new();

    setup(&mut params, k);
    params.print();

    let (fID1, fID2): (BIG, BIG) = extract(&params, &id);
    println!("f(ID1): {}", big_to_hex(&fID1));
    println!("f(ID2): {}", big_to_hex(&fID2));
    //println!("Total operation time: {:?}", start_total.elapsed());

    let mut rng = gen_seed();

    // Prover's commitment
    let (g_r, r) = commit(&params, &mut rng);
    println!(
        "Prover Commitment (g^r): {:?}",
        (ecp_to_hex(&g_r.0), ecp_to_hex(&g_r.1))
    );

    // Verifier's challenges
    let (c1, c2) = challenge(&params, &mut rng);
    println!(
        "Verifier Challenges: {:?}",
        (big_to_hex(&c1), big_to_hex(&c2))
    );

    // Prover's responses
    let (s1, s2) = respond(&r, &(c1, c2), &(fID1, fID2), params.get_order());
    println!("Prover Responses: {:?}", (big_to_hex(&s1), big_to_hex(&s2)));

    // Verifier's check
    let is_valid = verify(&params, &g_r, &(s1, s2), &(c1, c2), &id);
    println!("Verification result: {}", is_valid);
}

pub fn gen_seed() -> RAND {
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND::new();
    rng.clean();
    OsRng.fill_bytes(&mut raw);
    rng.seed(100, &raw);
    rng
}

pub fn hash_to_big(data: &[u8]) -> BIG {
    let mut sha = SHA3::new(SHAKE256);
    for &byte in data {
        sha.process(byte);
    }
    let mut output = [0u8; big::MODBYTES];
    sha.shake(&mut output, big::MODBYTES);
    BIG::frombytes(&output)
}

pub fn big_to_hex(b: &big::BIG) -> String {
    let mut bytes = [0u8; big::MODBYTES];
    b.tobytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub fn hex_to_big(hex: &str) -> big::BIG {
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).unwrap_or(0);
        bytes.push(byte);
    }
    while bytes.len() < big::MODBYTES {
        bytes.insert(0, 0);
    }
    let mut byte_array = [0u8; big::MODBYTES];
    byte_array.copy_from_slice(&bytes[..big::MODBYTES]);
    big::BIG::frombytes(&byte_array)
}

pub fn ecp_to_hex(p: &ecp::ECP) -> String {
    if p.is_infinity() {
        return String::from("infinity");
    }
    let wx = p.getx();
    let wy = p.gety();
    format!("({}, {})", big_to_hex(&wx), big_to_hex(&wy))
}
pub fn string_to_bytes(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}
