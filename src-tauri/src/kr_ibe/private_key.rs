extern crate mcore;

use mcore::ed25519::big;

#[derive(Clone)]
pub struct PrivateKey {
    f1ID: big::BIG,
    f2ID: big::BIG,
    h1ID: big::BIG,
    h2ID: big::BIG,
    p1ID: big::BIG,
    p2ID: big::BIG,
}

impl PrivateKey {
    pub fn new() -> Self {
        PrivateKey {
            f1ID: big::BIG::new(),
            f2ID: big::BIG::new(),
            h1ID: big::BIG::new(),
            h2ID: big::BIG::new(),
            p1ID: big::BIG::new(),
            p2ID: big::BIG::new(),
        }
    }

    pub fn set_private_key(&mut self, f1ID: big::BIG, f2ID: big::BIG, h1ID: big::BIG, h2ID: big::BIG, p1ID: big::BIG, p2ID: big::BIG) {
        self.f1ID = f1ID;
        self.f2ID = f2ID;
        self.h1ID = h1ID;
        self.h2ID = h2ID;
        self.p1ID = p1ID;
        self.p2ID = p2ID;
    }

    pub fn get_f1ID(&self) -> &big::BIG {
        &self.f1ID
    }

    pub fn get_f2ID(&self) -> &big::BIG {
        &self.f2ID
    }

    pub fn get_h1ID(&self) -> &big::BIG {
        &self.h1ID
    }

    pub fn get_h2ID(&self) -> &big::BIG {
        &self.h2ID
    }

    pub fn get_p1ID(&self) -> &big::BIG {
        &self.p1ID
    }

    pub fn get_p2ID(&self) -> &big::BIG {
        &self.p2ID
    }

    pub fn print(&self) {
        println!("========Begin Private Key=========");
        println!("f1ID: {}", big_to_hex(&self.f1ID));
        println!("f2ID: {}", big_to_hex(&self.f2ID));
        println!("h1ID: {}", big_to_hex(&self.h1ID));
        println!("h2ID: {}", big_to_hex(&self.h2ID));
        println!("p1ID: {}", big_to_hex(&self.p1ID));
        println!("p2ID: {}", big_to_hex(&self.p2ID));
        println!("========End of Private Key=========");
    }

    pub fn format_full(&self) -> String {
        let mut output = String::new();
        output.push_str("========Begin Private Key=========\n");

        output.push_str(&format!("f1ID: {}\n", big_to_hex(&self.f1ID)));
        output.push_str(&format!("f2ID: {}\n", big_to_hex(&self.f2ID)));
        output.push_str(&format!("h1ID: {}\n", big_to_hex(&self.h1ID)));
        output.push_str(&format!("h2ID: {}\n", big_to_hex(&self.h2ID)));
        output.push_str(&format!("p1ID: {}\n", big_to_hex(&self.p1ID)));
        output.push_str(&format!("p2ID: {}\n", big_to_hex(&self.p2ID)));

        output.push_str("========End of Private Key=========\n");
        output
    }
}

fn big_to_hex(b: &big::BIG) -> String {
    let mut bytes = [0u8; big::MODBYTES];
    b.tobytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}
