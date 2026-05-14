use crate::system::state::APP_STATE;
use crate::kr_paeks::main as krpaeks_core;
use crate::system::utils::keyword_hash;

pub fn search(user: &str, keyword: &str) -> Result<Vec<usize>, String> {
    let state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.active_sessions.get(user).unwrap_or(&false) {
        return Err("User is not authenticated.".to_string());
    }

    let paeks_params = state
        .paeks_params
        .as_ref()
        .ok_or("PAEKS params not initialised.")?;

    let receiver_paeks = state
        .paeks_users
        .get(user)
        .ok_or("Receiver PAEKS keypair missing.")?;

    let keyword_big = krpaeks_core::hash_to_big(keyword);

    let mut results = Vec::new();

    for (index, data) in state.database.iter().enumerate() {
        if data.owner != user {
            continue;
        }

        let sender_paeks = match state.paeks_users.get(&data.sender) {
            Some(keys) => keys,
            None => continue,
        };

        let trapdoor = krpaeks_core::trapdoor(
            paeks_params,
            &sender_paeks.pk,
            &receiver_paeks.sk,
            &keyword_big,
        );

        let search_hash = keyword_hash(keyword);

        if data.keyword_hash != search_hash {
            continue;
        }

        let matched = krpaeks_core::test(&data.paeks_index, &trapdoor);

        println!(
            "Search debug => keyword: {}, index: {}, owner: {}, sender: {}, matched: {}",
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

    println!("Search result count: {}", results.len());

    Ok(results)
}