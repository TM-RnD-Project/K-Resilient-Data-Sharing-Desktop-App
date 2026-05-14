use crate::system::state::{APP_STATE, SharedPayload};
use crate::kr_ibe::{main as kribe_core, plaintext::Plaintext};

pub fn download(user: &str, index: usize) -> Result<SharedPayload, String> {
    let state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.active_sessions.get(user).unwrap_or(&false) {
        return Err("User is not authenticated.".to_string());
    }

    let params = state
        .ibe_params
        .as_ref()
        .ok_or("IBE params not initialised.")?
        .clone();

    let sk = state
        .users
        .get(user)
        .ok_or("User private key not found.")?
        .clone();

    let data = state
        .database
        .get(index)
        .ok_or("Invalid ciphertext index.")?;

    if data.owner != user {
        return Err("Access denied. This ciphertext does not belong to this user.".to_string());
    }

    let mut ct = data.ct.clone();

    drop(state);

    let mut pt = Plaintext::new();

    kribe_core::decryption(&params, &sk, &mut ct, &mut pt);

    let plaintext = pt.to_string();
    match serde_json::from_str::<SharedPayload>(&plaintext) {
        Ok(payload) => Ok(payload),
        Err(_) => Ok(SharedPayload {
            payload_type: "text".to_string(),
            content: plaintext,
            file_name: None,
            mime_type: None,
            content_base64: None,
        }),
    }
}
