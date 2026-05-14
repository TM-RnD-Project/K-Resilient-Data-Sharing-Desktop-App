extern crate mcore;
use mcore::ed25519::big;
use mcore::rand::RAND;
use std::fmt;
use rand::RngCore;

#[derive(Clone)]
/// Polynomial operations.
pub struct Polynomial {
    degree: usize,
    coeff: Vec<big::BIG>,
    order: big::BIG,
}

impl Polynomial {

    pub fn new() -> Self {
        Polynomial {
            degree: 0,
            coeff: Vec::new(),
            order: big::BIG::new(),
        }
    }

    pub fn new_polynomial(degree: usize, order: big::BIG) -> Self {
        let mut rng = gen_seed();

        let mut coeff = vec![big::BIG::new(); degree];

        for i in 0..degree {
            coeff[i] = big::BIG::randomnum(&order, &mut rng);
        }
        
        Polynomial { degree, coeff, order }
    }

    pub fn evaluate(&self, x: &big::BIG) -> big::BIG {
        let mut accum = big::BIG::new();
        for j in 0..self.degree {
            let exp = big::BIG::new_int(j as isize);
            let mut x_clone = x.clone();
            let t2 = big::BIG::modmul(&self.coeff[j], &x_clone.powmod(&exp, &self.order), &self.order);
            accum.add(&t2);
            accum.rmod(&self.order);
        }
        accum
    }

    pub fn get_degree(&self) -> usize {
        self.degree
    }

    pub fn get_coeff(&self) -> &Vec<big::BIG> {
        &self.coeff
    }

    pub fn get_coeff_at(&self, i: usize) -> &big::BIG {
        &self.coeff[i]
    }

    pub fn get_order(&self) -> &big::BIG {
        &self.order
    }

    pub fn fmt(&self) -> String {
        let mut str = String::new();
        str.push_str("\n========Begin Polynomial=========\n");
        str.push_str(&format!("degree: {}\n", self.degree));
        str.push_str(&format!("order: {}\n",big_to_hex(&self.order)));

        for (i, coeff) in self.coeff.iter().enumerate() {
            str.push_str(&format!("coeff[{}]: {}\n", i, big_to_hex(&coeff)));
        }
        str.push_str("========End of Polynomial========\n");
        return str;
    }

}

fn big_to_hex(b: &big::BIG) -> String {
    let mut bytes = [0u8; big::MODBYTES];
    b.tobytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn gen_seed() -> RAND {
    let mut rng = RAND::new();
    let mut seed = [0u8; 100];
    rand::thread_rng().fill_bytes(&mut seed);
    rng.clean();
    rng.seed(100, &seed);
    rng
}