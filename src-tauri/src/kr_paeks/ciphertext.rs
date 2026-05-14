extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;
use mysql::serde;
use serde::Serialize;
use serde::Deserialize;

// #[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct Ciphertext {
    pub c1: ecp::ECP,
    pub c2: ecp::ECP,
    pub u: big::BIG,
}

impl Ciphertext {
    // Constructor (equivalent to Java's constructors)
    pub fn new() -> Self {
        Ciphertext { 
            c1: ecp::ECP::new(), 
            c2: ecp::ECP::new(), 
            u: big::BIG::new() 
        }
    }

    pub fn new_ciphertext(c1: &ecp::ECP, c2: &ecp::ECP, u: &big::BIG) -> Self {
        Ciphertext {
            c1: c1.clone(),
            c2: c2.clone(),
            u: u.clone(),
        }
    }

    // Setters (not strictly necessary in Rust, but provided for completeness)
    pub fn set_ciphertext(&mut self, c1: ecp::ECP, c2: ecp::ECP, u: big::BIG) {
        self.c1 = c1;
        self.c2 = c2;
        self.u = u;
    }

    pub fn set_c1(&mut self, c1: ecp::ECP) {
        self.c1 = c1;
    }

    pub fn set_c2(&mut self, c2: ecp::ECP) {
        self.c2 = c2;
    }

    pub fn set_u(&mut self, u: big::BIG) {
        self.u = u;
    }

    pub fn print(&self) {
        println!("========Begin Ciphertext=========");
        println!("C1: {}", ecp_to_hex(&self.c1));
        println!("C2: {}", ecp_to_hex(&self.c2));
        println!("U: {}", big_to_hex(&self.u));
        println!("========End of Ciphertext=========");
    }
    pub fn format_full(&self) -> String {
        format!(
            "C1: {}\nC2: {}\nU: {}",
            ecp_to_hex(&self.c1),
            ecp_to_hex(&self.c2),
            big_to_hex(&self.u)
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}
