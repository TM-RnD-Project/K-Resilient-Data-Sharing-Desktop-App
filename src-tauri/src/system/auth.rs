use crate::kr_ibi::main as kribi_core;
use crate::kr_peks::{self, utils::*};
use crate::system::state::LoginSession;
use crate::system::state::APP_STATE;
use crate::system::utils::id_to_bytes;

pub fn login_start(id: &str) -> Result<(String, String), String> {
    let mut state = APP_STATE.lock().unwrap();

    if !state.users.contains_key(id) {
        return Err("User is not registered. Please register first.".to_string());
    }

    if state.ibi_params.is_none() {
        panic!("IBI params not initialised. Call setup_all() first.");
    }

    let params = state.ibi_params.as_ref().unwrap();

    let mut rng = kribi_core::gen_seed();

    let (g_r, r) = kribi_core::commit(params, &mut rng);
    let (c1, c2) = kribi_core::challenge(params, &mut rng);

    println!("Login start for ID: {}", id);

    state
        .login_sessions
        .insert(id.to_string(), LoginSession { g_r, c1, c2, r });

    Ok((kribi_core::big_to_hex(&c1), kribi_core::big_to_hex(&c2)))
}

pub fn login_respond(id: &str) -> Result<(String, String), String> {
    let mut state = APP_STATE.lock().unwrap();

    if !state.users.contains_key(id) {
        return Err("User is not registered. Please register first.".to_string());
    }

    let params = state.ibi_params.as_ref().unwrap();
    let session = state.login_sessions.get(id).unwrap();

    let mut id_bytes = id_to_bytes(id);

    if id_bytes.len() < 32 {
        id_bytes.resize(32, 0);
    }

    let (f1, f2) = kribi_core::extract(params, &id_bytes);

    let (s1, s2) = kribi_core::respond(
        &session.r,
        &(session.c1, session.c2),
        &(f1, f2),
        params.get_order(),
    );

    Ok((kribi_core::big_to_hex(&s1), kribi_core::big_to_hex(&s2)))
}

pub fn login_verify(id: &str, s1_hex: &str, s2_hex: &str) -> Result<bool, String> {
    let mut state = APP_STATE.lock().unwrap();

    if !state.users.contains_key(id) {
        return Err("User is not registered. Please register first.".to_string());
    }

    let params = state.ibi_params.as_ref().unwrap();
    let session = state.login_sessions.get(id).unwrap();

    let s1 = kribi_core::hex_to_big(s1_hex);
    let s2 = kribi_core::hex_to_big(s2_hex);

    let mut id_bytes = id_to_bytes(id);

    let valid = kribi_core::verify(
        params,
        &session.g_r,
        &(s1, s2),
        &(session.c1, session.c2),
        &id_bytes,
    );

    if valid {
        state.active_sessions.insert(id.to_string(), true);
    }

    Ok(valid)
}
