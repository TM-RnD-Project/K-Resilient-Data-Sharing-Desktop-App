extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;
use std::fmt;

pub struct Trapdoor {
    pub t1: ecp::ECP,
    pub t2: ecp::ECP,
    pub u_cap: big::BIG,
}

impl Trapdoor {
    // Constructor
    pub fn new() -> Self {
        Trapdoor { 
            t1: ecp::ECP::new(), 
            t2: ecp::ECP::new(), 
            u_cap: big::BIG::new()
        }
    }

    pub fn new_trapdoor(t1: &ecp::ECP, t2: &ecp::ECP, u_cap: &big::BIG) -> Self {
        Trapdoor {
            t1: t1.clone(),
            t2: t2.clone(),
            u_cap: u_cap.clone()
        }
    }

    // Setter (if necessary)
    pub fn set_trapdoor(&mut self, t1: ecp::ECP, t2: ecp::ECP, u_cap: big::BIG) {
        self.t1 = t1;
        self.t2 = t2;
        self.u_cap = u_cap;
    }

    // Custom to_string function
    pub fn print(&self) {
        println!("========Begin Trapdoor=========");
        println!("t1: {}", ecp_to_hex(&self.t1));
        println!("t2: {}", ecp_to_hex(&self.t2));
        println!("u_cap: {}", big_to_hex(&self.u_cap));
        println!("========End of Trapdoor=========");
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("t1: {}\n", ecp_to_hex(&self.t1)));
        output.push_str(&format!("t2: {}\n", ecp_to_hex(&self.t2)));
        output.push_str(&format!("u_cap: {}\n", big_to_hex(&self.u_cap)));
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