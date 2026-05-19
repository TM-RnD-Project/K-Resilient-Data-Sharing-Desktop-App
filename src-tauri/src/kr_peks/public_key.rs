use super::utils::*;
use mcore::ed25519::big;
use mcore::ed25519::ecdh;
use mcore::ed25519::ecp;

pub struct PublicKey {
    Dt: Vec<ecp::ECP>,
}

impl PublicKey {
    pub fn new() -> Self {
        PublicKey { Dt: Vec::new() }
    }

    pub fn new_public_key(Dt: Vec<ecp::ECP>) -> Self {
        PublicKey { Dt: Dt }
    }

    pub fn set_public_key(&mut self, Dt: Vec<ecp::ECP>) {
        self.Dt = Dt;
    }

    pub fn get_Dt(&self) -> &Vec<ecp::ECP> {
        &self.Dt
    }

    pub fn get_Dt_i(&self, i: usize) -> &ecp::ECP {
        &self.Dt[i]
    }

    pub fn print(&self) {
        println!();
        println!("========Begin Public Key=========");
        for i in 0..self.Dt.len() {
            println!("Dt[{}]: {}", i, ecp_to_hex(&self.Dt[i]));
        }
        println!("========End of Public Key=========");
    }

    pub fn is_valid(&self) -> isize {
        for p in &self.Dt {
            let mut bytes = [0u8; 2 * big::MODBYTES + 1];
            p.tobytes(&mut bytes, false);

            let result = ecdh::public_key_validate(&bytes);
            if result != 0 {
                return result;
            }
        }
        0
    }

    pub fn format_full(&self) -> String {
        let mut result = String::new();
        for i in 0..self.Dt.len() {
            result.push_str(&format!("Dt[{}]: {}\n", i, ecp_to_hex(&self.Dt[i])));
        }
        result
    }
}
