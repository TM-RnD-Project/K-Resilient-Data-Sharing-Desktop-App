extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;

pub struct Params {
    k: usize,
    order: big::BIG,
    g: ecp::ECP,
    Dt1: Vec<ecp::ECP>,
    Dt2: Vec<ecp::ECP>,
    msk1: Vec<big::BIG>,
    msk2: Vec<big::BIG>,
}

impl Params {
    pub fn new() -> Self {
        Params {
            k: 0,
            order: big::BIG::new(),
            g: ecp::ECP::new(),
            Dt1: Vec::new(),
            Dt2: Vec::new(),
            msk1: Vec::new(),
            msk2: Vec::new(),
        }
    }

    pub fn set_params(
        &mut self,
        k: usize,
        order: big::BIG,
        g: ecp::ECP,
        Dt1: Vec<ecp::ECP>,
        Dt2: Vec<ecp::ECP>,
        msk1: Vec<big::BIG>,
        msk2: Vec<big::BIG>,
    ) {
        self.k = k;
        self.order = order;
        self.g = g;
        self.Dt1 = Dt1;
        self.Dt2 = Dt2;
        self.msk1 = msk1;
        self.msk2 = msk2;
    }

    pub fn get_k(&self) -> usize {
        self.k
    }

    pub fn get_order(&self) -> &big::BIG {
        &self.order
    }

    pub fn get_g(&self) -> &ecp::ECP {
        &self.g
    }

    pub fn get_msk1(&self) -> &Vec<big::BIG> {
        &self.msk1
    }

    pub fn get_msk2(&self) -> &Vec<big::BIG> {
        &self.msk2
    }

    pub fn get_Dt1(&self) -> &Vec<ecp::ECP> {
        &self.Dt1
    }

    pub fn get_Dt2(&self) -> &Vec<ecp::ECP> {
        &self.Dt2
    }

    pub fn print(&self) {
        println!("k: {}", self.k);
        println!("Order: {}", big_to_hex(&self.order));
        println!("g: {}", ecp_to_hex(&self.g));
        for i in 0..self.Dt1.len() {
            println!("Dt1[{}]: {}", i, ecp_to_hex(&self.Dt1[i]));
            println!("Dt2[{}]: {}", i, ecp_to_hex(&self.Dt2[i]));
        }
        for i in 0..self.msk1.len() {
            println!("msk1[{}]: {}", i, big_to_hex(&self.msk1[i]));
            println!("msk2[{}]: {}", i, big_to_hex(&self.msk2[i]));
        }
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();
        output.push_str("========Begin Params=========\n");
        output.push_str(&format!("k: {}\n", self.k));
        output.push_str(&format!("order: {}\n", big_to_hex(&self.order)));
        output.push_str(&format!("g: {}\n", ecp_to_hex(&self.g)));
        for i in 0..self.Dt1.len() {
            output.push_str(&format!("Dt1[{}]: {}\n", i, ecp_to_hex(&self.Dt1[i])));
            output.push_str(&format!("Dt2[{}]: {}\n", i, ecp_to_hex(&self.Dt2[i])));
        }
        for i in 0..self.msk1.len() {
            output.push_str(&format!("msk1[{}]: {}\n", i, big_to_hex(&self.msk1[i])));
            output.push_str(&format!("msk2[{}]: {}\n", i, big_to_hex(&self.msk2[i])));
        }
        output.push_str("========End Params=========");
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
