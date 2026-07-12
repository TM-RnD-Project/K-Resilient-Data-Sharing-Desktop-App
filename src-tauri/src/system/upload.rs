use crate::system::state::{SearchIndex, SearchScheme, SharedPayload, StoredData, APP_STATE};
use crate::system::utils::{id_to_bytes, record_aad};

use crate::kr_ibe::{ciphertext::Ciphertext as IbeCiphertext, main as kribe_core};

use crate::kr_paeks::main as krpaeks_core;
use crate::kr_peks::main as krpeks_core;

pub fn upload(
    sender: &str,
    receiver: &str,
    msg: &str,
    keyword: &str,
    scheme: &str,
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

    let selected_scheme = match scheme.to_lowercase().as_str() {
        "peks" => SearchScheme::Peks,
        "paeks" => SearchScheme::Paeks,
        _ => return Err("Invalid search scheme. Use 'peks' or 'paeks'.".to_string()),
    };

    let search_index = match selected_scheme {
        SearchScheme::Peks => {
            let peks_params = state
                .peks_params
                .as_ref()
                .ok_or("PEKS params not initialised.")?;

            let peks_pk = state.peks_pk.as_ref().ok_or("PEKS public key missing.")?;

            let keyword_bytes = keyword.as_bytes().to_vec();

            let index = krpeks_core::peks(peks_params, peks_pk, &keyword_bytes)
                .ok_or("KR-PEKS encryption failed.")?;

            SearchIndex::Peks(index)
        }

        SearchScheme::Paeks => {
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

            let keyword_big = krpaeks_core::hash_to_big(keyword);

            let index = krpaeks_core::encrypt(
                paeks_params,
                &receiver_paeks.pk,
                &sender_paeks.sk,
                &keyword_big,
            );

            SearchIndex::Paeks(index)
        }
    };

    let aad = record_aad(
        sender,
        receiver,
        selected_scheme.as_str(),
        &search_index.format_full(),
    );
    let receiver_bytes = id_to_bytes(receiver);
    let msg_bytes = payload_json.as_bytes().to_vec();
    let mut ibe_ct = IbeCiphertext::new();
    kribe_core::encryption_with_aad(ibe_params, &mut ibe_ct, &receiver_bytes, &msg_bytes, &aad)?;

    state.database.push(StoredData {
        ct: ibe_ct,
        search_index,
        search_scheme: selected_scheme,
        sender: sender.to_string(),
        owner: receiver.to_string(),
    });

    Ok(())
}
