use super::utils::*;
use mcore::ed25519::big;
use mcore::ed25519::ecp;

pub struct Params {
    k: usize,
    order: big::BIG,
    g1: ecp::ECP,
    g2: ecp::ECP,
}

impl Params {
    pub fn new() -> Self {
        Params {
            k: 0,
            order: big::BIG::new(),
            g1: ecp::ECP::new(),
            g2: ecp::ECP::new(),
        }
    }

    pub fn new_params(k: &usize, order: &big::BIG, g1: &ecp::ECP, g2: &ecp::ECP) -> Self {
        Params {
            k: *k,
            order: *order,
            g1: g1.clone(),
            g2: g2.clone(),
        }
    }

    pub fn set_params(&mut self, k: usize, order: big::BIG, g1: ecp::ECP, g2: ecp::ECP) {
        self.k = k;
        self.order = order;
        self.g1 = g1;
        self.g2 = g2;
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

    pub fn print(&self) {
        println!();
        println!("========Begin Params=========");
        println!("g1: {}", ecp_to_hex(&self.g1));
        println!("g2: {}", ecp_to_hex(&self.g2));
        println!("order: {}", big_to_hex(&self.order));
        println!("k: {}", self.k);
        println!("========End of Params=========");
    }

    pub fn is_valid(&self) -> bool {
        if self.k == 0
            || big::BIG::comp(&self.order, &big::BIG::new()) == 0
            || self.g1.is_infinity()
            || self.g2.is_infinity()
        {
            return false;
        }
        true
    }

    pub fn format_full(&self) -> String {
        format!(
            "g1: {}\ng2: {}\norder: {}\nk: {}",
            ecp_to_hex(&self.g1),
            ecp_to_hex(&self.g2),
            big_to_hex(&self.order),
            self.k
        )
    }
}
