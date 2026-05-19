use super::polynomial::Polynomial;

pub struct PrivateKey {
    p1: Polynomial,
    p2: Polynomial,
}

impl PrivateKey {
    pub fn new() -> Self {
        PrivateKey {
            p1: Polynomial::new(),
            p2: Polynomial::new(),
        }
    }

    pub fn new_private_key(p1: Polynomial, p2: Polynomial) -> Self {
        PrivateKey { p1, p2 }
    }

    pub fn set_private_key(&mut self, p1: Polynomial, p2: Polynomial) {
        self.p1 = p1;
        self.p2 = p2;
    }

    pub fn get_p1(&self) -> &Polynomial {
        &self.p1
    }

    pub fn get_p2(&self) -> &Polynomial {
        &self.p2
    }

    pub fn print(&self) {
        println!();
        println!("========Begin Private Key=========");
        println!("P1:");
        self.p1.print();
        println!("P2:");
        self.p2.print();
        println!("========End of Private Key=========");
    }

    pub fn is_valid(&self) -> bool {
        if !self.p1.is_valid() || !self.p2.is_valid() {
            return false;
        }
        true
    }

    pub fn format_full(&self) -> String {
        format!(
            "P1:\n{}\nP2:\n{}",
            self.p1.format_full(),
            self.p2.format_full()
        )
    }
}
