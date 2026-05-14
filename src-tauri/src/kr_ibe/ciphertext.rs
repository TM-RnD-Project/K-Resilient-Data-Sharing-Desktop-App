extern crate mcore;

use mcore::ed25519::big;
use mcore::ed25519::ecp;

#[derive(Clone)]
pub struct Ciphertext {
    u1: ecp::ECP,
    u2: ecp::ECP,
    c: ecp::ECP,
    v_id: ecp::ECP,
    aes_cipher:Vec<u8>,
}

impl Ciphertext {
    pub fn new() -> Self {
        Ciphertext {
            u1: ecp::ECP::new(),
            u2: ecp::ECP::new(),
            c: ecp::ECP::new(),
            v_id: ecp::ECP::new(),
            aes_cipher: Vec::new(),
        }
    }

    pub fn new_ciphertext(u1: &ecp::ECP, u2: &ecp::ECP, c: &ecp::ECP, v_id: &ecp::ECP, aes_cipher: Vec<u8>) -> Self {
        Ciphertext {u1:u1.clone(), u2:u2.clone(), c:c.clone(), v_id:v_id.clone(), aes_cipher}
    }

    pub fn set_ciphertext(&mut self, u1: ecp::ECP, u2: ecp::ECP, c: ecp::ECP, v_id: ecp::ECP, aes_cipher: Vec<u8>) {
        self.u1 = u1;
        self.u2 = u2;
        self.c = c;
        self.v_id = v_id;
        self.aes_cipher = aes_cipher;
    }

    pub fn get_u1(&self) -> &ecp::ECP {
        &self.u1
    }

    pub fn get_u2(&self) -> &ecp::ECP {
        &self.u2
    }

    pub fn get_c(&self) -> &ecp::ECP {
        &self.c
    }

    pub fn get_v_id(&self) -> &ecp::ECP {
        &self.v_id
    }

    pub fn get_aes_cipher(&self) -> &Vec<u8> {
        &self.aes_cipher
    }

    pub fn print(&self) {
        println!("========Begin Ciphertext=========");
        println!("u1: {}", ecp_to_hex(&self.u1));
        println!("u2: {}", ecp_to_hex(&self.u2));
        println!("c: {}", ecp_to_hex(&self.c));
        println!("v_id: {}", ecp_to_hex(&self.v_id));
        println!("aes_cipher: {}", bytes_to_hex(&self.aes_cipher));
        println!("========End of Ciphertext=========");
    }

    pub fn format_full(&self) -> String {
        let mut str = String::new();
        str.push_str("\n========Begin Ciphertext=========\n");
        str.push_str(&format!("u1: {}\n", ecp_to_hex(&self.u1)));
        str.push_str(&format!("u2: {}\n", ecp_to_hex(&self.u2)));
        str.push_str(&format!("c: {}\n", ecp_to_hex(&self.c)));
        str.push_str(&format!("v_id: {}\n", ecp_to_hex(&self.v_id)));
        str.push_str(&format!("aes_cipher: {}\n", bytes_to_hex(&self.aes_cipher)));
        str.push_str("========End of Ciphertext========\n");
        return str;
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}