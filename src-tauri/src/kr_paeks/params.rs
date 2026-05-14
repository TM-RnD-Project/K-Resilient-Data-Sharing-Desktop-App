extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;
use std::fmt;

pub struct Params {
    pub g1: ecp::ECP,
    pub g2: ecp::ECP,
    pub order: big::BIG,
    pub msk: big::BIG,
    pub k: usize,
}

impl Params {
    // Constructor (equivalent to Java's constructor)
    pub fn new() -> Self {
        Params { 
            g1: ecp::ECP::new(), 
            g2: ecp::ECP::new(), 
            msk: big::BIG::new(), 
            order: big::BIG::new(), 
            k: 0,
        }
    }

    // Setters (explicit setters only if needed)
    pub fn set_params(&mut self, g1: ecp::ECP, g2: ecp::ECP, msk: big::BIG, order: big::BIG, k: usize) {
        self.g1 = g1;
        self.g2 = g2;
        self.msk = msk;
        self.order = order;
        self.k = k;
    }

    pub fn get_k(&self) -> usize {
        self.k
    }

    pub fn get_order(&self) -> &big::BIG {
        &self.order
    }

    pub fn get_g1(&self) -> &ecp::ECP {
        &self.g1
    }

    pub fn get_g2(&self) -> &ecp::ECP {
        &self.g2
    }

    // Custom to_string function
    pub fn print(&self) {
        println!("========Begin Params=========");
        println!("k: {}", self.k);
        println!("order: {}", big_to_hex(&self.order));
        println!("msk: {}", big_to_hex(&self.msk));
        println!("g1: {}", ecp_to_hex(&self.g1));
        println!("g2: {}", ecp_to_hex(&self.g2));
        println!("========End of Params=========");
    }

    pub fn format_full(&self) -> String {
        format!(
            "k: {}\norder: {}\nmsk: {}\ng1: {}\ng2: {}",
            self.k,
            big_to_hex(&self.order),
            big_to_hex(&self.msk),
            ecp_to_hex(&self.g1),
            ecp_to_hex(&self.g2)
        )
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
