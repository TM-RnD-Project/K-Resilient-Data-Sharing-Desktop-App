extern crate mcore;

pub struct Plaintext {
    plaintext: String,
}

impl Plaintext {
    pub fn new() -> Self {
        Plaintext {
            plaintext: String::new(),
        }
    }

    pub fn new_plaintext(plaintext: String) -> Self {
        Plaintext { plaintext }
    }

    pub fn set_plaintext(&mut self, plaintext: String) {
        self.plaintext = plaintext;
    }

    pub fn print(&self) {
        println!("========Begin Plaintext=========");
        println!("plaintext: {}", self.plaintext);
        println!("========End of Plaintext=========");
    }

    pub fn to_string(&self) -> String {
        self.plaintext.clone()
    }

    pub fn format_full(&self) -> String {
        format!("Plaintext: {}", self.plaintext)
    }
}
