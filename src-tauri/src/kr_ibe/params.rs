extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;

use super::polynomial;
use super::polynomial::Polynomial;

#[derive(Clone)]
pub struct Params {
    k: usize,
    order: big::BIG,
    g1: ecp::ECP,
    g2: ecp::ECP,
    At: Vec<ecp::ECP>,
    Bt: Vec<ecp::ECP>,
    Dt: Vec<ecp::ECP>,
    f1: polynomial::Polynomial,
    f2: polynomial::Polynomial,
    h1: polynomial::Polynomial,
    h2: polynomial::Polynomial,
    p1: polynomial::Polynomial,
    p2: polynomial::Polynomial,
}

impl Params {
    pub fn new() -> Self {
        Params {
            k: 0,
            order: big::BIG::new(),
            g1: ecp::ECP::new(),
            g2: ecp::ECP::new(),
            At: Vec::new(),
            Bt: Vec::new(),
            Dt: Vec::new(),
            f1: Polynomial::new(),
            f2: Polynomial::new(),
            h1: Polynomial::new(),
            h2: Polynomial::new(),
            p1: Polynomial::new(),
            p2: Polynomial::new(),
        }
    }

    pub fn new_params(
        k: &usize,
        order: &big::BIG,
        g1: &ecp::ECP,
        g2: &ecp::ECP,
        At: &Vec<ecp::ECP>,
        Bt: &Vec<ecp::ECP>,
        Dt: &Vec<ecp::ECP>,
        f1: polynomial::Polynomial,
        f2: polynomial::Polynomial,
        h1: polynomial::Polynomial,
        h2: polynomial::Polynomial,
        p1: polynomial::Polynomial,
        p2: polynomial::Polynomial,
    ) -> Self {
        Params {
            k: *k,
            order: *order,
            g1: g1.clone(),
            g2: g2.clone(),
            At: At.clone(),
            Bt: Bt.clone(),
            Dt: Dt.clone(),
            f1: f1,
            f2: f2,
            h1: h1,
            h2: h2,
            p1: p1,
            p2: p2,
        }
    }

    pub fn set_params(
        &mut self,
        k: usize,
        order: big::BIG,
        g1: ecp::ECP,
        g2: ecp::ECP,
        At: Vec<ecp::ECP>,
        Bt: Vec<ecp::ECP>,
        Dt: Vec<ecp::ECP>,
        f1: polynomial::Polynomial,
        f2: polynomial::Polynomial,
        h1: polynomial::Polynomial,
        h2: polynomial::Polynomial,
        p1: polynomial::Polynomial,
        p2: polynomial::Polynomial,
    ) {
        self.k = k;
        self.order = order;
        self.g1 = g1;
        self.g2 = g2;
        self.At = At;
        self.Bt = Bt;
        self.Dt = Dt;
        self.f1 = f1;
        self.f2 = f2;
        self.h1 = h1;
        self.h2 = h2;
        self.p1 = p1;
        self.p2 = p2;
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

    pub fn get_At(&self) -> &Vec<ecp::ECP> {
        &self.At
    }

    pub fn get_Bt(&self) -> &Vec<ecp::ECP> {
        &self.Bt
    }

    pub fn get_Dt(&self) -> &Vec<ecp::ECP> {
        &self.Dt
    }

    pub fn get_f1(&self) -> &Polynomial {
        &self.f1
    }

    pub fn get_f2(&self) -> &Polynomial {
        &self.f2
    }

    pub fn get_h1(&self) -> &Polynomial {
        &self.h1
    }

    pub fn get_h2(&self) -> &Polynomial {
        &self.h2
    }

    pub fn get_p1(&self) -> &Polynomial {
        &self.p1
    }

    pub fn get_p2(&self) -> &Polynomial {
        &self.p2
    }

    pub fn print(&self) {
        println!("========Begin Params=========");
        println!("k: {}", self.k);
        println!("order: {}", big_to_hex(&self.order));
        println!("g1: {}", ecp_to_hex(&self.g1));
        println!("g2: {}", ecp_to_hex(&self.g2));

        for i in 0..self.At.len() {
            println!("At[{}]: {}", i, ecp_to_hex(&self.At[i]));
        }
        for i in 0..self.Bt.len() {
            println!("Bt[{}]: {}", i, ecp_to_hex(&self.Bt[i]));
        }
        for i in 0..self.Dt.len() {
            println!("Dt[{}]: {}", i, ecp_to_hex(&self.Dt[i]));
        }
        for i in 0..self.f1.get_degree() {
            println!("f1[{}]: {}", i, big_to_hex(&self.f1.get_coeff_at(i)));
        }
        for i in 0..self.f2.get_degree() {
            println!("f2[{}]: {}", i, big_to_hex(&self.f2.get_coeff_at(i)));
        }
        for i in 0..self.h1.get_degree() {
            println!("h1[{}]: {}", i, big_to_hex(&self.h1.get_coeff_at(i)));
        }
        for i in 0..self.h2.get_degree() {
            println!("h2[{}]: {}", i, big_to_hex(&self.h2.get_coeff_at(i)));
        }
        for i in 0..self.p1.get_degree() {
            println!("p1[{}]: {}", i, big_to_hex(&self.p1.get_coeff_at(i)));
        }
        for i in 0..self.p2.get_degree() {
            println!("p2[{}]: {}", i, big_to_hex(&self.p2.get_coeff_at(i)));
        }
        println!("========End of Params=========");
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();

        output.push_str("========Begin Params=========\n");
        output.push_str(&format!("k: {}\n", self.k));
        output.push_str(&format!("order: {}\n", big_to_hex(&self.order)));
        output.push_str(&format!("g1: {}\n", ecp_to_hex(&self.g1)));
        output.push_str(&format!("g2: {}\n", ecp_to_hex(&self.g2)));

        for i in 0..self.At.len() {
            output.push_str(&format!("At[{}]: {}\n", i, ecp_to_hex(&self.At[i])));
        }
        for i in 0..self.Bt.len() {
            output.push_str(&format!("Bt[{}]: {}\n", i, ecp_to_hex(&self.Bt[i])));
        }
        for i in 0..self.Dt.len() {
            output.push_str(&format!("Dt[{}]: {}\n", i, ecp_to_hex(&self.Dt[i])));
        }
        for i in 0..self.f1.get_degree() {
            output.push_str(&format!(
                "f1[{}]: {}\n",
                i,
                big_to_hex(&self.f1.get_coeff_at(i))
            ));
        }
        for i in 0..self.f2.get_degree() {
            output.push_str(&format!(
                "f2[{}]: {}\n",
                i,
                big_to_hex(&self.f2.get_coeff_at(i))
            ));
        }
        for i in 0..self.h1.get_degree() {
            output.push_str(&format!(
                "h1[{}]: {}\n",
                i,
                big_to_hex(&self.h1.get_coeff_at(i))
            ));
        }
        for i in 0..self.h2.get_degree() {
            output.push_str(&format!(
                "h2[{}]: {}\n",
                i,
                big_to_hex(&self.h2.get_coeff_at(i))
            ));
        }
        for i in 0..self.p1.get_degree() {
            output.push_str(&format!(
                "p1[{}]: {}\n",
                i,
                big_to_hex(&self.p1.get_coeff_at(i))
            ));
        }
        for i in 0..self.p2.get_degree() {
            output.push_str(&format!(
                "p2[{}]: {}\n",
                i,
                big_to_hex(&self.p2.get_coeff_at(i))
            ));
        }
        output.push_str("========End of Params=========\n");

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
