pub fn id_to_bytes(id: &str) -> Vec<u8> {
    let mut bytes = id.as_bytes().to_vec();

    if bytes.len() < 32 {
        bytes.resize(32, 0);
    }

    bytes
}

use sha2::{Digest, Sha256};

pub fn record_aad(sender: &str, receiver: &str, mode: &str, search_index_repr: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"KR-DS-v1|record-aad|");

    for value in [sender, receiver, mode, search_index_repr] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }

    hasher.finalize().to_vec()
}
