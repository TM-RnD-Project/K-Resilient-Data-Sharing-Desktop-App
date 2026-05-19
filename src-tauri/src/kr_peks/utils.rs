use base64::*;
use mcore::ed25519::big;
use mcore::ed25519::ecp;
use mcore::rand::RAND;
use mcore::sha3::{SHA3, SHAKE256};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{self, BufReader, BufWriter};

use super::ciphertext::Ciphertext;
use super::params::Params;
use super::polynomial::Polynomial;
use super::private_key::PrivateKey;
use super::public_key::PublicKey;

pub fn gen_seed() -> RAND {
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND::new();
    rng.clean();
    OsRng.fill_bytes(&mut raw);
    rng.seed(100, &raw);
    rng
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

pub fn string_to_bytes(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}

pub fn big_to_bytes(b: &big::BIG) -> Vec<u8> {
    let mut bytes = vec![0u8; big::MODBYTES];
    b.tobytes(&mut bytes);
    bytes
}

pub fn bytes_to_big(b: &[u8]) -> big::BIG {
    big::BIG::frombytes(b)
}

pub fn ecp_to_bytes(p: &ecp::ECP) -> Vec<u8> {
    let mut bytes = vec![0u8; 2 * big::MODBYTES + 1];
    p.tobytes(&mut bytes, false);
    bytes
}

pub fn bytes_to_ecp(b: &[u8]) -> ecp::ECP {
    ecp::ECP::frombytes(b)
}

pub fn big_to_hex(b: &big::BIG) -> String {
    big_to_bytes(&b)
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

pub fn ecp_to_hex(p: &ecp::ECP) -> String {
    let bytes = ecp_to_bytes(&p);
    let x_bytes = &bytes[1..big::MODBYTES + 1];
    let y_bytes = &bytes[big::MODBYTES + 1..];

    let x_hex: String = x_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    let y_hex: String = y_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();

    format!("({}, {})", x_hex, y_hex)
}

pub fn export_params(params: &Params, file_path: &str) -> io::Result<()> {
    let data = json!({
        "k": encode(params.get_k().to_ne_bytes()),
        "order": encode(big_to_bytes(params.get_order())),
        "g1": encode(ecp_to_bytes(params.get_g1())),
        "g2": encode(ecp_to_bytes(params.get_g2()))
    });

    let mut writer = BufWriter::new(File::create(file_path)?);
    serde_json::to_writer(&mut writer, &data)?;

    Ok(())
}

pub fn import_params(params: &mut Params, file_path: &str) -> io::Result<()> {
    let reader = BufReader::new(File::open(file_path)?);
    let data: Value = serde_json::from_reader(reader)?;

    let k = usize::from_ne_bytes(
        decode(
            data["k"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64")
        .try_into()
        .expect("Failed to convert to [u8; 8]"),
    );

    let order = bytes_to_big(
        &decode(
            data["order"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64"),
    );

    let g1 = bytes_to_ecp(
        &decode(
            data["g1"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64"),
    );

    let g2 = bytes_to_ecp(
        &decode(
            data["g2"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64"),
    );

    params.set_params(k, order, g1, g2);

    Ok(())
}

pub fn poly_to_string(p: &Polynomial) -> Value {
    let coeff_str: Vec<String> = p
        .get_coeff()
        .iter()
        .map(|c| encode(&big_to_bytes(c)))
        .collect();

    let data = json!({
        "degree": encode(p.get_degree().to_ne_bytes()),
        "order": encode(big_to_bytes(p.get_order())),
        "coeff": coeff_str.join("\n")
    });

    data
}

pub fn string_to_poly(s: &Value) -> Polynomial {
    let degree = usize::from_ne_bytes(
        decode(
            s["degree"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64")
        .try_into()
        .expect("Failed to convert to [u8; 8]"),
    );

    let order = bytes_to_big(
        &decode(
            s["order"]
                .as_str()
                .expect("Failed to get a valid string from JSON"),
        )
        .expect("Failed to decode base64"),
    );

    let coeff_str = s["coeff"]
        .as_str()
        .expect("Failed to get a valid string from JSON");
    let mut coeff = Vec::new();
    for line in coeff_str.lines() {
        coeff.push(bytes_to_big(
            &decode(line).expect("Failed to decode base64"),
        ));
    }

    let mut p = Polynomial::new();
    p.set_polynomial(degree, coeff, order);
    p
}

pub fn export_sk(sk: &PrivateKey, file_path: &str) -> io::Result<()> {
    let data = json!({
        "p1": poly_to_string(sk.get_p1()),
        "p2": poly_to_string(sk.get_p2())
    });

    let mut writer = BufWriter::new(File::create(file_path)?);
    serde_json::to_writer(&mut writer, &data)?;

    Ok(())
}

pub fn import_sk(sk: &mut PrivateKey, file_path: &str) -> io::Result<()> {
    let reader = BufReader::new(File::open(file_path)?);
    let data: Value = serde_json::from_reader(reader)?;

    let p1 = string_to_poly(&data["p1"]);
    let p2 = string_to_poly(&data["p2"]);

    sk.set_private_key(p1, p2);

    Ok(())
}

pub fn export_pk(pk: &PublicKey, file_path: &str) -> io::Result<()> {
    if pk.is_valid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to export public key: Public key is invalid!",
        ));
    }

    let base64_strings: Vec<String> = pk
        .get_Dt()
        .iter()
        .map(|ecp| encode(&ecp_to_bytes(ecp)))
        .collect();

    let data = json!({
        "Dt": base64_strings.join("\n")
    });

    let mut writer = BufWriter::new(File::create(file_path)?);
    serde_json::to_writer(&mut writer, &data)?;

    Ok(())
}

pub fn import_pk(pk: &mut PublicKey, file_path: &str) -> io::Result<()> {
    let reader = BufReader::new(File::open(file_path)?);
    let data: Value = serde_json::from_reader(reader)?;

    let Dt_str = data["Dt"]
        .as_str()
        .expect("Failed to get a valid string from JSON");

    let mut Dt = Vec::new();
    for line in Dt_str.lines() {
        Dt.push(bytes_to_ecp(
            &decode(line).expect("Failed to decode base64"),
        ));
    }

    pk.set_public_key(Dt);

    Ok(())
}

pub fn export_c(c: &Ciphertext, file_path: &str) -> io::Result<()> {
    let data = json!({
        "u1": encode(ecp_to_bytes(c.get_u1())),
        "u2": encode(ecp_to_bytes(c.get_u2())),
        "sw": encode(ecp_to_bytes(c.get_sw()))
    });

    let mut writer = BufWriter::new(File::create(file_path)?);
    serde_json::to_writer(&mut writer, &data)?;

    Ok(())
}

pub fn import_c(c: &mut Ciphertext, file_path: &str) -> io::Result<()> {
    let reader = BufReader::new(File::open(file_path)?);
    let data: Value = serde_json::from_reader(reader)?;

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

    c.set_ciphertext(u1, u2, sw);

    Ok(())
}
