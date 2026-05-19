use crate::system::state::{SearchIndex, SearchScheme, APP_STATE};
use crate::system::utils::keyword_hash;

use crate::kr_paeks::main as krpaeks_core;
use crate::kr_peks::main as krpeks_core;

pub fn search(user: &str, keyword: &str, scheme: &str) -> Result<Vec<usize>, String> {
    let state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.active_sessions.get(user).unwrap_or(&false) {
        return Err("User is not authenticated.".to_string());
    }

    let selected_scheme = match scheme.to_lowercase().as_str() {
        "peks" => SearchScheme::Peks,
        "paeks" => SearchScheme::Paeks,
        _ => return Err("Invalid search scheme. Use 'peks' or 'paeks'.".to_string()),
    };

    let search_hash = keyword_hash(keyword);
    let mut results = Vec::new();

    match selected_scheme {
        SearchScheme::Peks => {
            let peks_params = state
                .peks_params
                .as_ref()
                .ok_or("PEKS params not initialised.")?;

            let peks_sk = state.peks_sk.as_ref().ok_or("PEKS private key missing.")?;

            let keyword_bytes = keyword.as_bytes().to_vec();

            let trapdoor = krpeks_core::trapdoor(peks_params, peks_sk, &keyword_bytes);

            for (index, data) in state.database.iter().enumerate() {
                if data.owner != user {
                    continue;
                }

                if data.keyword_hash != search_hash {
                    continue;
                }

                if let SearchIndex::Peks(peks_index) = &data.search_index {
                    let matched = krpeks_core::test(peks_index, &trapdoor);

                    println!(
                        "PEKS search debug => keyword: {}, index: {}, owner: {}, sender: {}, matched: {}",
                        keyword,
                        index,
                        data.owner,
                        data.sender,
                        matched
                    );

                    if matched {
                        results.push(index);
                    }
                }
            }
        }

        SearchScheme::Paeks => {
            let paeks_params = state
                .paeks_params
                .as_ref()
                .ok_or("PAEKS params not initialised.")?;

            let receiver_paeks = state
                .paeks_users
                .get(user)
                .ok_or("Receiver PAEKS keypair missing.")?;

            let keyword_big = krpaeks_core::hash_to_big(keyword);

            for (index, data) in state.database.iter().enumerate() {
                if data.owner != user {
                    continue;
                }

                if data.keyword_hash != search_hash {
                    continue;
                }

                let sender_paeks = match state.paeks_users.get(&data.sender) {
                    Some(keys) => keys,
                    None => continue,
                };

                if let SearchIndex::Paeks(paeks_index) = &data.search_index {
                    let trapdoor = krpaeks_core::trapdoor(
                        paeks_params,
                        &sender_paeks.pk,
                        &receiver_paeks.sk,
                        &keyword_big,
                    );

                    let matched = krpaeks_core::test(paeks_index, &trapdoor);

                    println!(
                        "PAEKS search debug => keyword: {}, index: {}, owner: {}, sender: {}, matched: {}",
                        keyword,
                        index,
                        data.owner,
                        data.sender,
                        matched
                    );

                    if matched {
                        results.push(index);
                    }
                }
            }
        }
    }

    println!("Search result count: {}", results.len());

    Ok(results)
}
