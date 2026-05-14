extern crate mcore;

use mcore::ed25519::ecp;
use mcore::ed25519::big;
use std::fmt;

#[derive(Clone)]
pub struct PublicKey {
    pub dt: Vec<ecp::ECP>,
}

impl PublicKey {
    // Constructor
    pub fn new() -> Self {
        PublicKey { 
            dt: Vec::new(),
        }
    }

    // Setter
    pub fn set_public_key(&mut self, dt: Vec<ecp::ECP>) {
        self.dt = dt;
    }

    // Getter (returns a reference to avoid unnecessary cloning)
    pub fn get_public_key(&self) -> &Vec<ecp::ECP> {
        &self.dt
    }

    // Get specific index
    pub fn get_public_key_at(&self, i: usize) -> Option<&ecp::ECP> {
        self.dt.get(i)
    }

    // Custom to_string function

    pub fn print(&self) {
        // println!("========Begin Public Key=========");
        for i in 0..self.dt.len() {
            println!("dt[{}]: {}", i, ecp_to_hex(&self.dt[i]));
        }
        // println!("========End of Public Key=========");
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();
        for i in 0..self.dt.len() {
            output.push_str(&format!("dt[{}]: {}\n", i, ecp_to_hex(&self.dt[i])));
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
