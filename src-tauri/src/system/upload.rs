use crate::system::state::{APP_STATE, SharedPayload, StoredData};
use crate::system::utils::id_to_bytes;
use crate::system::utils::keyword_hash;

use crate::kr_ibe::{main as kribe_core, ciphertext::Ciphertext as IbeCiphertext};
use crate::kr_paeks::main as krpaeks_core;

pub fn upload(
    sender: &str,
    receiver: &str,
    msg: &str,
    keyword: &str,
    payload_type: &str,
    file_name: Option<String>,
    mime_type: Option<String>,
    content_base64: Option<String>,
) -> Result<(), String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.active_sessions.get(sender).unwrap_or(&false) {
        return Err("Sender is not authenticated.".to_string());
    }

    if !state.users.contains_key(receiver) {
        return Err("Receiver is not registered.".to_string());
    }

    let ibe_params = state
        .ibe_params
        .as_ref()
        .ok_or("IBE params not initialised.")?;

    let paeks_params = state
        .paeks_params
        .as_ref()
        .ok_or("PAEKS params not initialised.")?;

    let sender_paeks = state
        .paeks_users
        .get(sender)
        .ok_or("Sender PAEKS keypair missing.")?;

    let receiver_paeks = state
        .paeks_users
        .get(receiver)
        .ok_or("Receiver PAEKS keypair missing.")?;

    let mut ibe_ct = IbeCiphertext::new();

    let receiver_bytes = id_to_bytes(receiver);
    let payload = match payload_type {
        "text" => SharedPayload {
            payload_type: "text".to_string(),
            content: msg.to_string(),
            file_name: None,
            mime_type: None,
            content_base64: None,
        },
        "file" | "image" => {
            let content_base64 = content_base64
                .filter(|content| !content.is_empty())
                .ok_or("File content is missing.")?;

            SharedPayload {
                payload_type: payload_type.to_string(),
                content: msg.to_string(),
                file_name,
                mime_type,
                content_base64: Some(content_base64),
            }
        }
        _ => return Err("Unsupported payload type.".to_string()),
    };

    let payload_json = serde_json::to_string(&payload)
        .map_err(|error| format!("Failed to serialise upload payload: {error}"))?;
    let msg_bytes = payload_json.as_bytes().to_vec();

    kribe_core::encryption(
        ibe_params,
        &mut ibe_ct,
        &receiver_bytes,
        &msg_bytes,
    );

    let keyword_big = krpaeks_core::hash_to_big(keyword);

    let paeks_index = krpaeks_core::encrypt(
        paeks_params,
        &receiver_paeks.pk,
        &sender_paeks.sk,
        &keyword_big,
    );

    state.database.push(StoredData {
        ct: ibe_ct,
        paeks_index,
        sender: sender.to_string(),
        owner: receiver.to_string(),
        keyword_hash: keyword_hash(keyword),
    });

    Ok(())
}
