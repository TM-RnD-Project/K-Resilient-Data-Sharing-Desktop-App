extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;

use super::polynomial;
use super::polynomial::Polynomial;
use std::fmt;

#[derive(Clone)]
pub struct PrivateKey {
    pub p1: polynomial::Polynomial,
    pub p2: polynomial::Polynomial,
}

impl PrivateKey {
    // Constructor (equivalent to Java's constructor)
    pub fn new() -> Self {
        PrivateKey { 
            p1: Polynomial::new(), 
            p2: Polynomial::new(), 
        }
    }

    // Setters (explicit setters only if needed)
    pub fn set_private_key(&mut self, p1: Polynomial, p2: Polynomial) {
        self.p1 = p1;
        self.p2 = p2;
    }

    pub fn get_p1(&self) -> &Polynomial {
        &self.p1
    }

    pub fn get_p2(&self) -> &Polynomial {
        &self.p2
    }

    pub fn print(&self) {
        // println!("========Begin Private Key=========");
        for i in 0..self.p1.get_degree() {
            println!("P1[{}]: {}", i, big_to_hex(&self.p1.get_coeff_at(i)));
        }
        for i in 0..self.p2.get_degree() {
            println!("P2[{}]: {}", i, big_to_hex(&self.p2.get_coeff_at(i)));
        }
        // println!("========End of Private Key=========");
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();
        for i in 0..self.p1.get_degree() {
            output.push_str(&format!("P1[{}]: {}\n", i, big_to_hex(&self.p1.get_coeff_at(i))));
        }
        for i in 0..self.p2.get_degree() {
            output.push_str(&format!("P2[{}]: {}\n", i, big_to_hex(&self.p2.get_coeff_at(i))));
        }
        output
    }

}

fn big_to_hex(b: &big::BIG) -> String {
    let mut bytes = [0u8; big::MODBYTES];
    b.tobytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn ecp_to_hex(p: &ecp::ECP) -> String {
    if p.is_infinity() {
        return String::from("infinity");
    }
    let wx = p.getx();
    let wy = p.gety();
    format!("({}, {})", big_to_hex(&wx), big_to_hex(&wy))
}