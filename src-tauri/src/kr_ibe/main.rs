#![allow(non_snake_case)]

use super::ciphertext::Ciphertext;
use super::params::Params;
use super::plaintext::Plaintext;
use super::polynomial;
use super::private_key::PrivateKey;

extern crate mcore;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use generic_array::typenum::U32;
use generic_array::GenericArray;
use mcore::ed25519::big;
use mcore::ed25519::big::MODBYTES;
use mcore::ed25519::ecdh;
use mcore::ed25519::ecp;
use mcore::ed25519::rom;
use mcore::rand::RAND;
use mcore::sha3::{SHA3, SHAKE256};
use rand::RngCore;

use std::time::Instant;

pub fn setup(params: &mut Params, k: usize) {
    let order = big::BIG::new_ints(&rom::CURVE_ORDER);

    let mut rng = gen_seed();
    let r = big::BIG::randomnum(&order, &mut rng);

    let g1 = ecp::ECP::generator();
    let g2 = g1.mul(&r);

    //validate g1 and g2
    if is_valid(&g1) != 0 {
        println!("g1 is invalid! Abort!");
        std::process::abort();
    }

    if is_valid(&g2) != 0 {
        println!("g2 is invalid! Abort!");
        std::process::abort();
    }

    //Choose the six random k-degree polynomials from Zq
    let f1 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);
    let f2 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);
    let h1 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);
    let h2 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);
    let p1 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);
    let p2 = polynomial::Polynomial::Gennew(k, &big::BIG::randomnum(&order, &mut rng), &order);

    //Compute At, Bt, Dt
    let mut At = vec![ecp::ECP::new(); k];
    let mut Bt = vec![ecp::ECP::new(); k];
    let mut Dt = vec![ecp::ECP::new(); k];

    for i in 0..k {
        At[i] = g1.mul(&f1.get_coeff_at(i));
        At[i].add(&g2.mul(&f2.get_coeff_at(i)));

        Bt[i] = g1.mul(&h1.get_coeff_at(i));
        Bt[i].add(&g2.mul(&h2.get_coeff_at(i)));

        Dt[i] = g1.mul(&p1.get_coeff_at(i));
        Dt[i].add(&g2.mul(&p2.get_coeff_at(i)));
    }

    //Set the params
    params.set_params(k, order, g1, g2, At, Bt, Dt, f1, f2, h1, h2, p1, p2);
}

pub fn extract(params: &Params, sk: &mut PrivateKey, id: &Vec<u8>) {
    let order = params.get_order();

    //get the value of each polynomial
    let f1 = params.get_f1();
    let f2 = params.get_f2();
    let h1 = params.get_h1();
    let h2 = params.get_h2();
    let p1 = params.get_p1();
    let p2 = params.get_p2();

    //Hash the string ID into BIG
    let hash_id = hash_to_big(id, order);

    //Return the secret key
    let f1ID = f1.evaluate(&hash_id);
    let f2ID = f2.evaluate(&hash_id);
    let h1ID = h1.evaluate(&hash_id);
    let h2ID = h2.evaluate(&hash_id);
    let p1ID = p1.evaluate(&hash_id);
    let p2ID = p2.evaluate(&hash_id);

    sk.set_private_key(f1ID, f2ID, h1ID, h2ID, p1ID, p2ID);
}

pub fn encryption(params: &Params, ciphertext: &mut Ciphertext, id: &Vec<u8>, m: &Vec<u8>) {
    encryption_with_aad(params, ciphertext, id, m, b"").expect("KR-IBE payload encryption failed");
}

pub fn encryption_with_aad(
    params: &Params,
    ciphertext: &mut Ciphertext,
    id: &Vec<u8>,
    m: &Vec<u8>,
    aad: &[u8],
) -> Result<(), String> {
    let order = params.get_order();

    //get the value of params
    let g1 = params.get_g1();
    let g2 = params.get_g2();
    let At = params.get_At();
    let Bt = params.get_Bt();
    let Dt = params.get_Dt();

    //validate g1 and g2
    if is_valid(&g1) != 0 {
        println!("g1 is invalid! Abort!");
        std::process::abort();
    }
    if is_valid(&g2) != 0 {
        println!("g2 is invalid! Abort!");
        std::process::abort();
    }

    let mut rng = gen_seed();

    //Hash the string ID into BIG
    let mut hash_id = hash_to_big(id, order);

    //E1
    let r1 = big::BIG::randomnum(&order, &mut rng);

    //E2
    let u1 = g1.mul(&r1);

    //E3
    let u2 = g2.mul(&r1);

    //E4
    let mut A_id = At[0].mul(&hash_id.powmod(&big::BIG::new_int(0), order));

    for i in 1..At.len() {
        let i_isize: isize = i.try_into().unwrap();
        let temp = At[i].mul(&hash_id.powmod(&big::BIG::new_int(i_isize), order));
        A_id.add(&temp);
    }

    let mut B_id = Bt[0].mul(&hash_id.powmod(&big::BIG::new_int(0), order));

    for i in 1..Bt.len() {
        let i_isize: isize = i.try_into().unwrap();
        let temp = Bt[i].mul(&hash_id.powmod(&big::BIG::new_int(i_isize), order));
        B_id.add(&temp);
    }

    let mut D_id = Dt[0].mul(&hash_id.powmod(&big::BIG::new_int(0), order));

    for i in 1..Dt.len() {
        let i_isize: isize = i.try_into().unwrap();
        let temp = Dt[i].mul(&hash_id.powmod(&big::BIG::new_int(i_isize), order));
        D_id.add(&temp);
    }

    //E5
    let s = D_id.mul(&r1);

    // AES-GCM Encryption Start
    // Generate a random AES key
    let key = Aes256Gcm::generate_key(OsRng); //32 bytes

    //convert key to ecp in order to be encrypted by IBE
    let ecp_key = ecp::ECP::mapit(&key);
    let mut bytes_ecp_key: Vec<u8> = vec![0; MODBYTES + 1];
    ecp_key.tobytes(&mut bytes_ecp_key, true);

    //split the AES key, first 32 bytes to be key, last 12 bytes to be the nonce (maybe overlap)
    let (aes_key, aes_nonce) = split_key_nonce(&bytes_ecp_key);

    // Convert Vec<u8> to GenericArray
    let generic_key = vec_to_generic_array(aes_key); //32 bytes
    let cipher = Aes256Gcm::new(&generic_key);

    // Nonce (must be unique for every encryption operation)
    let nonce = Nonce::from_slice(&aes_nonce); // 12 bytes

    // AES Encrypt message m
    let aes_ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: m.as_ref(),
                aad,
            },
        )
        .map_err(|_| "AES-GCM payload encryption failed.".to_string())?;

    // AES-GCM Encryption End

    //E6
    let mut temp_m = ecp::ECP::frombytes(&bytes_ecp_key);
    temp_m.add(&s);
    let c = temp_m;

    //E7
    let mut temp_alpha = u1.clone();
    temp_alpha.add(&u2);
    temp_alpha.add(&c);
    let alpha = hash_ECP_to_big(temp_alpha);

    //E8
    let mut v_id = A_id.mul(&r1);
    let r1_alpha = big::BIG::modmul(&r1, &alpha, order);
    v_id.add(&B_id.mul(&r1_alpha));

    //E9
    ciphertext.set_ciphertext(u1, u2, c, v_id, aes_ciphertext);

    Ok(())
}

pub fn decryption(
    params: &Params,
    sk: &PrivateKey,
    ciphertext: &mut Ciphertext,
    plaintext: &mut Plaintext,
) {
    let _ = decryption_with_aad(params, sk, ciphertext, plaintext, b"");
}

pub fn decryption_with_aad(
    params: &Params,
    sk: &PrivateKey,
    ciphertext: &mut Ciphertext,
    plaintext: &mut Plaintext,
    aad: &[u8],
) -> Result<(), String> {
    let order = params.get_order();

    let u1 = ciphertext.get_u1();
    let u2 = ciphertext.get_u2();
    let c = ciphertext.get_c();
    let aes_cipher = ciphertext.get_aes_cipher();

    //D1
    let mut temp_alpha = u1.clone();
    temp_alpha.add(u2);
    temp_alpha.add(c);
    let alpha = hash_ECP_to_big(temp_alpha);

    //D2
    let v_id = ciphertext.get_v_id();

    let f1ID = sk.get_f1ID();
    let f2ID = sk.get_f2ID();
    let h1ID = sk.get_h1ID();
    let h2ID = sk.get_h2ID();

    let h1ID_alpha = big::BIG::modmul(h1ID, &alpha, order);
    let pow1 = big::BIG::modadd(f1ID, &h1ID_alpha, order);
    let mut temp_u1 = u1.clmul(&pow1, order);

    let h2ID_alpha = big::BIG::modmul(h2ID, &alpha, order);
    let pow2 = big::BIG::modadd(f2ID, &h2ID_alpha, order);
    let temp_u2 = u2.clmul(&pow2, order);

    temp_u1.add(&temp_u2);

    let temp_v_id = temp_u1;
    let is_equal_v_id = v_id.equals(&temp_v_id);

    if is_equal_v_id == true {
        //D3
        let p1ID = sk.get_p1ID();
        let p2ID = sk.get_p2ID();

        let temp_s1 = u1.clone();
        let temp_s2 = u2.clone();

        let mut temp_u1_p1ID = temp_s1.clmul(p1ID, order);
        let temp_u2_p2ID = temp_s2.clmul(p2ID, order);
        temp_u1_p1ID.add(&temp_u2_p2ID);
        let mut s = temp_u1_p1ID;

        //D4
        let mut temp_c = c.clone();
        temp_c.sub(&s);

        // AES-GCM Decryption Start
        // Convert ECP key back to AES key after IBE decryption
        let mut recovered_key = vec![0; MODBYTES + 1];
        temp_c.tobytes(&mut recovered_key, true);

        // Split the recovered AES key into aes_key and aes_nonce
        let (aes_key, aes_nonce) = split_key_nonce(&recovered_key);

        // Convert Vec<u8> to GenericArray
        let generic_key = vec_to_generic_array(aes_key); //32 bytes

        let cipher = Aes256Gcm::new(&generic_key);

        let nonce = Nonce::from_slice(&aes_nonce); // 12 bytes

        // Decrypt the AES ciphertext
        let decrypted_plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: aes_cipher.as_ref(),
                    aad,
                },
            )
            .map_err(|_| "AES-GCM payload authentication failed.".to_string())?;

        // Convert the decrypted plaintext from Vec<u8> to String
        let decrypted_string = String::from_utf8(decrypted_plaintext)
            .map_err(|_| "Decrypted payload is not valid UTF-8.".to_string())?;

        // AES-GCM Decryption End

        plaintext.set_plaintext(decrypted_string);
        Ok(())
    } else {
        Err("KR-IBE ciphertext validation failed for this private key.".to_string())
    }
}

fn main() {
    let w = "Urgent";
    let id = "alice@mail.com";
    let k = 20;

    // Convert strings to byte arrays
    let w_bytes = string_to_bytes(w);
    let id_bytes = string_to_bytes(id);

    let mut params = Params::new();
    let mut sk = PrivateKey::new();
    let mut ciphertext = Ciphertext::new();
    let mut plaintext = Plaintext::new();

    let start = Instant::now();
    setup(&mut params, k);
    let duration = start.elapsed();
    params.print();
    println!("Setup took: {:?}", duration);

    let start = Instant::now();
    extract(&params, &mut sk, &id_bytes);
    let duration = start.elapsed();
    sk.print();
    println!("Extract took: {:?}", duration);

    let start = Instant::now();
    encryption(&params, &mut ciphertext, &id_bytes, &w_bytes);
    let duration = start.elapsed();
    ciphertext.print();
    println!("Encryption took: {:?}", duration);

    let start = Instant::now();
    decryption(&params, &mut sk, &mut ciphertext, &mut plaintext);
    let duration = start.elapsed();
    plaintext.print();
    println!("Decryption took: {:?}", duration);
}

fn gen_seed() -> RAND {
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND::new();
    rng.clean();
    OsRng.fill_bytes(&mut raw);
    rng.seed(100, &raw);
    rng
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

pub fn hash_to_big(input: &[u8], order: &big::BIG) -> big::BIG {
    let mut hasher = SHA3::new(SHAKE256);
    hasher.process_array(input);
    let mut output = [0u8; big::MODBYTES];
    hasher.shake(&mut output, big::MODBYTES);
    let mut v = big::BIG::frombytes(&output);
    v.rmod(order);
    v
}

fn hash_ECP_to_big(input: ecp::ECP) -> big::BIG {
    let mut hasher = SHA3::new(SHAKE256);
    let mut b: Vec<u8> = vec![0; MODBYTES + 1];
    input.tobytes(&mut b, true);
    hasher.process_array(&b);
    let mut output = [0u8; MODBYTES];
    hasher.shake(&mut output, MODBYTES);
    big::BIG::frombytes(&output)
}

fn split_key_nonce(key_nonce: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let aes_key = key_nonce[0..32].to_vec(); // First 32 bytes
    let aes_nonce = key_nonce[key_nonce.len() - 12..key_nonce.len()].to_vec(); // Last 12 bytes

    (aes_key, aes_nonce)
}

fn vec_to_generic_array(vec: Vec<u8>) -> GenericArray<u8, U32> {
    generic_array::GenericArray::from_slice(&vec).clone()
}

fn string_to_bytes(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::utils::record_aad;

    fn aad(sender: &str, receiver: &str, mode: &str, tag: &str, index: &str) -> Vec<u8> {
        record_aad(sender, receiver, mode, tag, index)
    }

    fn decrypt_result(
        params: &Params,
        sk: &PrivateKey,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> Result<String, String> {
        let mut ciphertext = ciphertext.clone();
        let mut plaintext = Plaintext::new();
        decryption_with_aad(params, sk, &mut ciphertext, &mut plaintext, aad)?;
        Ok(plaintext.to_string())
    }

    #[test]
    fn record_context_authenticates_and_rejects_tampering_and_swaps() {
        let receiver = b"receiver@example.test".to_vec();
        let other_receiver = b"other@example.test".to_vec();
        let message = b"authenticated record payload".to_vec();
        let mut params = Params::new();
        setup(&mut params, 3);

        let mut receiver_sk = PrivateKey::new();
        extract(&params, &mut receiver_sk, &receiver);
        let mut other_receiver_sk = PrivateKey::new();
        extract(&params, &mut other_receiver_sk, &other_receiver);

        let correct_aad = aad(
            "alice@example.test",
            "receiver@example.test",
            "peks",
            "keyword-tag-1",
            "search-index-1",
        );
        let mut ciphertext = Ciphertext::new();
        encryption_with_aad(&params, &mut ciphertext, &receiver, &message, &correct_aad).unwrap();

        assert_eq!(
            decrypt_result(&params, &receiver_sk, &ciphertext, &correct_aad).unwrap(),
            "authenticated record payload"
        );

        let tampered_contexts = [
            aad(
                "mallory@example.test",
                "receiver@example.test",
                "peks",
                "keyword-tag-1",
                "search-index-1",
            ),
            aad(
                "alice@example.test",
                "other@example.test",
                "peks",
                "keyword-tag-1",
                "search-index-1",
            ),
            aad(
                "alice@example.test",
                "receiver@example.test",
                "paeks",
                "keyword-tag-1",
                "search-index-1",
            ),
            aad(
                "alice@example.test",
                "receiver@example.test",
                "peks",
                "wrong-keyword-tag",
                "search-index-1",
            ),
            aad(
                "alice@example.test",
                "receiver@example.test",
                "peks",
                "keyword-tag-1",
                "replacement-search-index",
            ),
        ];

        for tampered_aad in tampered_contexts {
            assert!(decrypt_result(&params, &receiver_sk, &ciphertext, &tampered_aad).is_err());
        }

        let second_aad = aad(
            "alice@example.test",
            "receiver@example.test",
            "peks",
            "keyword-tag-2",
            "search-index-2",
        );
        let mut second_ciphertext = Ciphertext::new();
        encryption_with_aad(
            &params,
            &mut second_ciphertext,
            &receiver,
            &b"second payload".to_vec(),
            &second_aad,
        )
        .unwrap();

        assert!(decrypt_result(&params, &receiver_sk, &ciphertext, &second_aad).is_err());
        assert!(decrypt_result(&params, &receiver_sk, &second_ciphertext, &correct_aad).is_err());
        assert!(decrypt_result(&params, &other_receiver_sk, &ciphertext, &correct_aad).is_err());
    }
}
