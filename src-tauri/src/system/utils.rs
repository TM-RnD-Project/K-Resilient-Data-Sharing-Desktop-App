pub fn id_to_bytes(id: &str) -> Vec<u8> {
    let mut bytes = id.as_bytes().to_vec();

    if bytes.len() < 32 {
        bytes.resize(32, 0);
    }

    bytes
}

use sha2::{Digest, Sha256};

pub fn keyword_hash(keyword: &str) -> String {
    let normalised = keyword.trim().to_lowercase();
    let digest = Sha256::digest(normalised.as_bytes());
    hex::encode(digest)
}
