use crate::kr_ibi::main as kribi_core;
use crate::system::state::{IbiCredential, LoginChallenge, APP_STATE};
use crate::system::utils::id_to_bytes;
use mcore::ed25519::{big, ecp};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LOGIN_CHALLENGE_TTL_MS: u128 = 5 * 60 * 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallengeResponse {
    pub challenge_id: String,
    pub c1: String,
    pub c2: String,
    pub expires_at_ms: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginProof {
    pub challenge_id: String,
    pub commitment_1: String,
    pub commitment_2: String,
    pub s1: String,
    pub s2: String,
}

pub fn login_start(id: &str) -> Result<LoginChallengeResponse, String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.users.contains_key(id) {
        return Err("User is not registered. Please register first.".to_string());
    }

    let params = state
        .ibi_verifier_params
        .as_ref()
        .ok_or("IBI verifier params not initialised. Call setup_all() first.")?;

    if params.has_master_secret() {
        return Err("Verifier parameters unexpectedly contain KR-IBI master secret.".to_string());
    }

    let mut rng = kribi_core::gen_seed();
    let (c1, c2) = kribi_core::challenge(params, &mut rng);
    let now = now_ms();
    let challenge_id = new_challenge_id();

    state.login_challenges.insert(
        challenge_id.clone(),
        LoginChallenge {
            identity: id.to_string(),
            c1: c1.clone(),
            c2: c2.clone(),
            issued_at_ms: now,
            expires_at_ms: now + LOGIN_CHALLENGE_TTL_MS,
        },
    );

    Ok(LoginChallengeResponse {
        challenge_id,
        c1: kribi_core::big_to_hex(&c1),
        c2: kribi_core::big_to_hex(&c2),
        expires_at_ms: now + LOGIN_CHALLENGE_TTL_MS,
    })
}

pub fn login_respond(id: &str, challenge_id: &str) -> Result<LoginProof, String> {
    let credential = {
        let state = APP_STATE.lock().map_err(|_| "State lock failed")?;
        state
            .local_ibi_credentials
            .get(id)
            .cloned()
            .ok_or("Local KR-IBI credential not found for this user.")?
    };

    login_respond_with_credential(id, challenge_id, &credential)
}

pub fn login_respond_with_credential(
    id: &str,
    challenge_id: &str,
    credential: &IbiCredential,
) -> Result<LoginProof, String> {
    if credential.identity != id {
        return Err("Credential identity does not match login identity.".to_string());
    }

    let challenge = {
        let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;
        let (challenge_identity, c1, c2, expires_at_ms) = {
            let challenge = state
                .login_challenges
                .get(challenge_id)
                .ok_or("Login challenge not found.")?;
            (
                challenge.identity.clone(),
                challenge.c1.clone(),
                challenge.c2.clone(),
                challenge.expires_at_ms,
            )
        };

        if challenge_identity != id {
            return Err("Login challenge identity does not match prover identity.".to_string());
        }

        if expires_at_ms <= now_ms() {
            state.login_challenges.remove(challenge_id);
            return Err("Login challenge has expired.".to_string());
        }

        (c1, c2)
    };

    let verifier_params = {
        let state = APP_STATE.lock().map_err(|_| "State lock failed")?;
        state
            .ibi_verifier_params
            .as_ref()
            .cloned()
            .ok_or("IBI verifier params not initialised. Call setup_all() first.")?
    };

    let mut rng = kribi_core::gen_seed();
    let (g_r, r) = kribi_core::commit(&verifier_params, &mut rng);
    let response = kribi_core::respond(
        &r,
        &challenge,
        &(credential.f1.clone(), credential.f2.clone()),
        verifier_params.get_order(),
    );

    Ok(LoginProof {
        challenge_id: challenge_id.to_string(),
        commitment_1: ecp_to_compressed_hex(&g_r.0),
        commitment_2: ecp_to_compressed_hex(&g_r.1),
        s1: kribi_core::big_to_hex(&response.0),
        s2: kribi_core::big_to_hex(&response.1),
    })
}

pub fn login_verify(
    id: &str,
    challenge_id: &str,
    commitment_1_hex: &str,
    commitment_2_hex: &str,
    s1_hex: &str,
    s2_hex: &str,
) -> Result<bool, String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;

    if !state.users.contains_key(id) {
        return Err("User is not registered. Please register first.".to_string());
    }

    let challenge = match state.login_challenges.remove(challenge_id) {
        Some(challenge) => challenge,
        None => return Err("Login challenge not found or already used.".to_string()),
    };

    if challenge.identity != id {
        return Err("Login challenge identity mismatch.".to_string());
    }

    if challenge.expires_at_ms <= now_ms() {
        return Err("Login challenge has expired.".to_string());
    }

    let params = state
        .ibi_verifier_params
        .as_ref()
        .ok_or("IBI verifier params not initialised. Call setup_all() first.")?;

    if params.has_master_secret() {
        return Err("Verifier parameters unexpectedly contain KR-IBI master secret.".to_string());
    }

    let commitment_1 = compressed_hex_to_ecp(commitment_1_hex)?;
    let commitment_2 = compressed_hex_to_ecp(commitment_2_hex)?;
    let s1 = kribi_core::hex_to_big(s1_hex);
    let s2 = kribi_core::hex_to_big(s2_hex);
    let id_bytes = id_to_bytes(id);

    let valid = kribi_core::verify(
        params,
        &(commitment_1, commitment_2),
        &(s1, s2),
        &(challenge.c1, challenge.c2),
        &id_bytes,
    );

    if valid {
        state.active_sessions.insert(id.to_string(), true);
    }

    Ok(valid)
}

pub fn logout(id: &str) -> Result<(), String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;
    state.active_sessions.remove(id);
    state
        .login_challenges
        .retain(|_, challenge| challenge.identity != id);
    Ok(())
}

pub fn invalidate_session(id: &str) -> Result<(), String> {
    logout(id)
}

pub fn clear_authentication_state() -> Result<(), String> {
    let mut state = APP_STATE.lock().map_err(|_| "State lock failed")?;
    state.login_challenges.clear();
    state.active_sessions.clear();
    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn new_challenge_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn ecp_to_compressed_hex(point: &ecp::ECP) -> String {
    let mut bytes = vec![0u8; big::MODBYTES + 1];
    point.tobytes(&mut bytes, true);
    hex::encode(bytes)
}

fn compressed_hex_to_ecp(value: &str) -> Result<ecp::ECP, String> {
    let bytes = hex::decode(value).map_err(|_| "Invalid compressed commitment hex.".to_string())?;
    if bytes.len() != big::MODBYTES + 1 {
        return Err("Invalid compressed commitment length.".to_string());
    }
    Ok(ecp::ECP::frombytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{download, search, setup, upload, user};
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn reset() {
        setup::setup_all(3);
    }

    fn register_pair() {
        user::register_user("alice@example.test").unwrap();
        user::register_user("bob@example.test").unwrap();
    }

    fn login_success(id: &str) -> LoginProof {
        let challenge = login_start(id).unwrap();
        let proof = login_respond(id, &challenge.challenge_id).unwrap();
        let verified = login_verify(
            id,
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .unwrap();
        assert!(verified);
        proof
    }

    #[test]
    fn ibi_registration_provisioning_and_verifier_separation() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        user::register_user("alice@example.test").unwrap();

        let state = APP_STATE.lock().unwrap();
        assert!(state
            .local_ibi_credentials
            .contains_key("alice@example.test"));
        assert!(state
            .ibi_issuer_params
            .as_ref()
            .unwrap()
            .has_master_secret());
        assert!(!state
            .ibi_verifier_params
            .as_ref()
            .unwrap()
            .has_master_secret());
        assert!(state.users.contains_key("alice@example.test"));
        assert!(!state.login_challenges.values().any(|challenge| {
            challenge.identity == "alice@example.test" && challenge.issued_at_ms == 0
        }));
    }

    #[test]
    fn ibi_login_accepts_valid_credential_and_rejects_invalid_cases() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        register_pair();

        login_success("alice@example.test");

        let challenge = login_start("alice@example.test").unwrap();
        let bob_credential = {
            let state = APP_STATE.lock().unwrap();
            state
                .local_ibi_credentials
                .get("bob@example.test")
                .unwrap()
                .clone()
        };
        assert!(login_respond_with_credential(
            "alice@example.test",
            &challenge.challenge_id,
            &bob_credential
        )
        .is_err());

        let challenge = login_start("alice@example.test").unwrap();
        let mut wrong_credential = {
            let state = APP_STATE.lock().unwrap();
            state
                .local_ibi_credentials
                .get("alice@example.test")
                .unwrap()
                .clone()
        };
        wrong_credential.f1 = bob_credential.f1.clone();
        let proof = login_respond_with_credential(
            "alice@example.test",
            &challenge.challenge_id,
            &wrong_credential,
        )
        .unwrap();
        assert!(!login_verify(
            "alice@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .unwrap());

        let challenge = login_start("alice@example.test").unwrap();
        let mut proof = login_respond("alice@example.test", &challenge.challenge_id).unwrap();
        proof.s1.replace_range(0..2, "00");
        assert!(!login_verify(
            "alice@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .unwrap());

        assert!(login_start("unknown@example.test").is_err());
    }

    #[test]
    fn ibi_challenge_lifecycle_and_session_logout() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        register_pair();

        let challenge = login_start("alice@example.test").unwrap();
        let proof = login_respond("alice@example.test", &challenge.challenge_id).unwrap();
        assert!(login_verify(
            "alice@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .unwrap());
        assert!(login_verify(
            "alice@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .is_err());
        assert!(!APP_STATE
            .lock()
            .unwrap()
            .login_challenges
            .contains_key(&proof.challenge_id));

        let challenge = login_start("alice@example.test").unwrap();
        let proof = login_respond("alice@example.test", &challenge.challenge_id).unwrap();
        assert!(login_verify(
            "bob@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .is_err());
        assert!(!APP_STATE
            .lock()
            .unwrap()
            .login_challenges
            .contains_key(&proof.challenge_id));

        let challenge = login_start("alice@example.test").unwrap();
        {
            let mut state = APP_STATE.lock().unwrap();
            state
                .login_challenges
                .get_mut(&challenge.challenge_id)
                .unwrap()
                .expires_at_ms = 0;
        }
        assert!(login_respond("alice@example.test", &challenge.challenge_id).is_err());
        let proof = LoginProof {
            challenge_id: challenge.challenge_id.clone(),
            commitment_1: "00".repeat(big::MODBYTES + 1),
            commitment_2: "00".repeat(big::MODBYTES + 1),
            s1: "00".repeat(big::MODBYTES),
            s2: "00".repeat(big::MODBYTES),
        };
        assert!(login_verify(
            "alice@example.test",
            &proof.challenge_id,
            &proof.commitment_1,
            &proof.commitment_2,
            &proof.s1,
            &proof.s2,
        )
        .is_err());
        assert!(!APP_STATE
            .lock()
            .unwrap()
            .login_challenges
            .contains_key(&proof.challenge_id));

        login_success("alice@example.test");
        upload::upload(
            "alice@example.test",
            "bob@example.test",
            "hello",
            "hello",
            "peks",
            "text",
            None,
            None,
            None,
        )
        .unwrap();
        login_success("bob@example.test");
        let results = search::search("bob@example.test", "hello", "peks").unwrap();
        assert!(!results.is_empty());
        let payload = download::download("bob@example.test", results[0]).unwrap();
        assert_eq!(payload.payload_type, "text");
        assert_eq!(payload.content, "hello");

        upload::upload(
            "alice@example.test",
            "bob@example.test",
            "file payload",
            "file",
            "peks",
            "file",
            Some("demo.txt".to_string()),
            Some("text/plain".to_string()),
            Some("ZmlsZSBieXRlcw==".to_string()),
        )
        .unwrap();
        let file_results = search::search("bob@example.test", "file", "peks").unwrap();
        let file_payload =
            download::download("bob@example.test", *file_results.last().unwrap()).unwrap();
        assert_eq!(file_payload.payload_type, "file");
        assert_eq!(file_payload.file_name.as_deref(), Some("demo.txt"));
        assert_eq!(
            file_payload.content_base64.as_deref(),
            Some("ZmlsZSBieXRlcw==")
        );

        upload::upload(
            "alice@example.test",
            "bob@example.test",
            "image payload",
            "image",
            "peks",
            "image",
            Some("demo.png".to_string()),
            Some("image/png".to_string()),
            Some("iVBORw0KGgo=".to_string()),
        )
        .unwrap();
        let image_results = search::search("bob@example.test", "image", "peks").unwrap();
        let image_payload =
            download::download("bob@example.test", *image_results.last().unwrap()).unwrap();
        assert_eq!(image_payload.payload_type, "image");
        assert_eq!(image_payload.mime_type.as_deref(), Some("image/png"));

        logout("bob@example.test").unwrap();
        assert!(search::search("bob@example.test", "hello", "peks").is_err());
        assert!(download::download("bob@example.test", results[0]).is_err());
    }
}
