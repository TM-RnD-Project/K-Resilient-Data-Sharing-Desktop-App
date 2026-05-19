use super::utils::*;
use mcore::ed25519::big;

pub struct Trapdoor {
    p1: big::BIG,
    p2: big::BIG,
}

impl Trapdoor {
    pub fn new() -> Self {
        Trapdoor {
            p1: big::BIG::new(),
            p2: big::BIG::new(),
        }
    }

    pub fn new_trapdoor(p1: &big::BIG, p2: &big::BIG) -> Self {
        Trapdoor {
            p1: p1.clone(),
            p2: p2.clone(),
        }
    }

    pub fn set_trapdoor(&mut self, p1: big::BIG, p2: big::BIG) {
        self.p1 = p1;
        self.p2 = p2;
    }

    pub fn get_p1(&self) -> &big::BIG {
        &self.p1
    }

    pub fn get_p2(&self) -> &big::BIG {
        &self.p2
    }

    pub fn print(&self) {
        println!();
        println!("========Begin Trapdoor=========");
        println!("p1: {}", big_to_hex(&self.p1));
        println!("p2: {}", big_to_hex(&self.p2));
        println!("========End of Trapdoor=========");
    }

    pub fn format_full(&self) -> String {
        format!("p1: {}\np2: {}", big_to_hex(&self.p1), big_to_hex(&self.p2))
    }
}
