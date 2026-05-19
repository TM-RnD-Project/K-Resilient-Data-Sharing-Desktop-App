use super::utils::ecp_to_hex;
use mcore::ed25519::ecp;

#[derive(Clone)]
pub struct Ciphertext {
    u1: ecp::ECP,
    u2: ecp::ECP,
    sw: ecp::ECP,
}

impl Ciphertext {
    pub fn new() -> Self {
        Ciphertext {
            u1: ecp::ECP::new(),
            u2: ecp::ECP::new(),
            sw: ecp::ECP::new(),
        }
    }

    pub fn new_ciphertext(u1: &ecp::ECP, u2: &ecp::ECP, sw: &ecp::ECP) -> Self {
        Ciphertext {
            u1: u1.clone(),
            u2: u2.clone(),
            sw: sw.clone(),
        }
    }

    pub fn set_ciphertext(&mut self, u1: ecp::ECP, u2: ecp::ECP, sw: ecp::ECP) {
        self.u1 = u1;
        self.u2 = u2;
        self.sw = sw;
    }

    pub fn get_u1(&self) -> &ecp::ECP {
        &self.u1
    }

    pub fn get_u2(&self) -> &ecp::ECP {
        &self.u2
    }

    pub fn get_sw(&self) -> &ecp::ECP {
        &self.sw
    }

    pub fn print(&self) {
        println!();
        println!("========Begin Ciphertext=========");
        println!("u1: {}", ecp_to_hex(&self.u1));
        println!("u2: {}", ecp_to_hex(&self.u2));
        println!("sw: {}", ecp_to_hex(&self.sw));
        println!("========End of Ciphertext=========");
    }

    pub fn is_valid(&self) -> bool {
        if self.u1.is_infinity() || self.u2.is_infinity() || self.sw.is_infinity() {
            return false;
        }
        true
    }

    pub fn format_full(&self) -> String {
        format!(
            "u1: {}\nu2: {}\nsw: {}",
            ecp_to_hex(&self.u1),
            ecp_to_hex(&self.u2),
            ecp_to_hex(&self.sw)
        )
    }
}
