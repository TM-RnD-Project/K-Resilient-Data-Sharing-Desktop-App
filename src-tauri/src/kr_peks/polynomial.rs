use super::utils::*;
use mcore::ed25519::big;

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

    pub fn set_polynomial(&mut self, degree: usize, coeff: Vec<big::BIG>, order: big::BIG) {
        self.degree = degree;
        self.coeff = coeff;
        self.order = order;
    }

    pub fn evaluate(&self, mut x: big::BIG) -> big::BIG {
        let mut accum = big::BIG::new_int(0);
    
        for i in 0..self.degree {
            let i_isize: isize = i.try_into().unwrap();
    
            let temp = big::BIG::modmul(&self.coeff[i], &big::BIG::powmod(&mut x, &big::BIG::new_int(i_isize), &self.order), &self.order);
            
            accum.add(&temp);
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

    pub fn get_coeff_i(&self, i: usize) -> &big::BIG {
        &self.coeff[i]
    }

    pub fn get_order(&self) -> &big::BIG {
        &self.order
    }

    pub fn print(&self) {
        println!("========Begin Polynomial=========");
        println!("degree: {}", self.degree);
        println!("order: {}", big_to_hex(&self.order));
        for i in 0..self.coeff.len() {
            println!("coeff[{}]: {}", i, big_to_hex(&self.coeff[i]));
        }
        println!("========End of Polynomial=========");
    }

    pub fn format_full(&self) -> String {
        let mut result = String::new();
        result.push_str(&format!("degree: {}\norder: {}\n", self.degree, big_to_hex(&self.order)));
        for i in 0..self.coeff.len() {
            result.push_str(&format!("coeff[{}]: {}\n", i, big_to_hex(&self.coeff[i])));
        }
        result
    }

    pub fn is_valid(&self) -> bool {
        if self.degree == 0 || big::BIG::comp(&self.order, &big::BIG::new()) == 0 || self.coeff.is_empty() || self.coeff.len() != self.degree {
            return false;
        }
        true
    }
}