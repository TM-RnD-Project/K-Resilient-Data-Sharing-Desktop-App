use tauri::command;

use super::main as krpaeks_core;
use crate::kr_paeks::ciphertext::Ciphertext;
use crate::kr_paeks::params::Params;
use crate::kr_paeks::private_key::PrivateKey;
use crate::kr_paeks::public_key::PublicKey;
use crate::kr_paeks::trapdoor::Trapdoor;

use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::Instant;

static PARAMS: Lazy<Mutex<Option<Params>>> = Lazy::new(|| Mutex::new(None));
static SENDER_SK: Lazy<Mutex<Option<PrivateKey>>> = Lazy::new(|| Mutex::new(None));
static SENDER_PK: Lazy<Mutex<Option<PublicKey>>> = Lazy::new(|| Mutex::new(None));
static RECEIVER_SK: Lazy<Mutex<Option<PrivateKey>>> = Lazy::new(|| Mutex::new(None));
static RECEIVER_PK: Lazy<Mutex<Option<PublicKey>>> = Lazy::new(|| Mutex::new(None));
static CIPHERTEXT: Lazy<Mutex<Option<Ciphertext>>> = Lazy::new(|| Mutex::new(None));
static TRAPDOOR: Lazy<Mutex<Option<Trapdoor>>> = Lazy::new(|| Mutex::new(None));
static TOTAL_RUNTIME: Lazy<Mutex<f64>> = Lazy::new(|| Mutex::new(0.0)); // total computation time

#[command]
pub fn kr_paeks_setup(k: usize) -> String {
    let start_time = Instant::now();

    let mut params = Params::new();
    krpaeks_core::setup(&mut params, k);

    let duration = start_time.elapsed();
    *PARAMS.lock().unwrap() = Some(params);
    *TOTAL_RUNTIME.lock().unwrap() = 0.0; // Reset runtime
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate setup

    let mut output = String::new();
    output.push_str("✅ KR-PAEKS Setup Complete!\n\n");
    output.push_str(&PARAMS.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🔵 Setup Time: {:.2?}\n", duration));

    output
}

#[command]
pub fn kr_paeks_keygen() -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    if let Some(ref params) = *params_lock {
        let mut sender_pk = PublicKey::new();
        let mut sender_sk = PrivateKey::new();
        let mut receiver_pk = PublicKey::new();
        let mut receiver_sk = PrivateKey::new();

        krpaeks_core::keygen(params, &mut sender_pk, &mut sender_sk);
        krpaeks_core::keygen(params, &mut receiver_pk, &mut receiver_sk);

        *SENDER_PK.lock().unwrap() = Some(sender_pk);
        *SENDER_SK.lock().unwrap() = Some(sender_sk);
        *RECEIVER_PK.lock().unwrap() = Some(receiver_pk);
        *RECEIVER_SK.lock().unwrap() = Some(receiver_sk);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate keygen

        let mut output = String::new();
        output.push_str("✅ KR-PAEKS Keygen Complete!\n\n");
        output.push_str("🔒 Sender Private Key:\n");
        output.push_str(&SENDER_SK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str("\n\n🔑 Sender Public Key:\n");
        output.push_str(&SENDER_PK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str("\n\n🔒 Receiver Private Key:\n");
        output.push_str(&RECEIVER_SK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str("\n\n🔑 Receiver Public Key:\n");
        output.push_str(&RECEIVER_PK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str(&format!(
            "\n🟢 Keygen Time: {}\n",
            format_runtime(duration.as_secs_f64())
        ));

        output
    } else {
        "❌ Error: KR-PAEKS setup not done yet!".into()
    }
}

#[command]
pub fn kr_paeks_encrypt(keyword: String) -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    let receiver_pk_lock = RECEIVER_PK.lock().unwrap();
    let sender_sk_lock = SENDER_SK.lock().unwrap();

    if let (Some(ref params), Some(ref receiver_pk), Some(ref sender_sk)) = (
        params_lock.as_ref(),
        receiver_pk_lock.as_ref(),
        sender_sk_lock.as_ref(),
    ) {
        let keyword_big = krpaeks_core::hash_to_big(&keyword);
        let ct = krpaeks_core::encrypt(params, receiver_pk, sender_sk, &keyword_big);

        *CIPHERTEXT.lock().unwrap() = Some(ct);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate encryption

        let mut output = String::new();
        output.push_str("✅ KR-PAEKS Encryption Complete!\n\n");
        output.push_str("📦 Ciphertext:\n");
        output.push_str(&CIPHERTEXT.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str(&format!(
            "\n🟣 Encryption Time: {}\n",
            format_runtime(duration.as_secs_f64())
        ));

        output
    } else {
        "❌ Error: Keygen not done yet!".into()
    }
}

#[command]
pub fn kr_paeks_trapdoor(keyword: String) -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    let sender_pk_lock = SENDER_PK.lock().unwrap();
    let receiver_sk_lock = RECEIVER_SK.lock().unwrap();

    if let (Some(ref params), Some(ref sender_pk), Some(ref receiver_sk)) = (
        params_lock.as_ref(),
        sender_pk_lock.as_ref(),
        receiver_sk_lock.as_ref(),
    ) {
        let keyword_big = krpaeks_core::hash_to_big(&keyword);
        let td = krpaeks_core::trapdoor(params, sender_pk, receiver_sk, &keyword_big);

        *TRAPDOOR.lock().unwrap() = Some(td);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate trapdoor

        let mut output = String::new();
        output.push_str("✅ KR-PAEKS Trapdoor Generation Complete!\n\n");
        output.push_str("🔑 Trapdoor:\n");
        output.push_str(&TRAPDOOR.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str(&format!(
            "\n🟠 Trapdoor Time: {}\n",
            format_runtime(duration.as_secs_f64())
        ));

        output
    } else {
        "❌ Error: Keygen not done yet!".into()
    }
}

#[command]
pub fn kr_paeks_test() -> String {
    let start_time = Instant::now();

    let ct_lock = CIPHERTEXT.lock().unwrap();
    let td_lock = TRAPDOOR.lock().unwrap();

    if let (Some(ref ct), Some(ref td)) = (ct_lock.as_ref(), td_lock.as_ref()) {
        let result = krpaeks_core::test(ct, td);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate test

        let total_runtime = *TOTAL_RUNTIME.lock().unwrap();

        let mut output = String::new();
        if result {
            output.push_str("✅ KR-PAEKS Test Successful!\n\n");
        } else {
            output.push_str("❌ KR-PAEKS Test Failed!\n\n");
        }

        output.push_str(&format!("⚡ Test Time: {:.2?}\n", duration));
        output.push_str(&format!(
            "🏁 Total Computation Time: {}\n",
            format_runtime(total_runtime)
        ));

        output
    } else {
        "❌ Error: Need to run encryption and trapdoor first!".into()
    }
}

fn format_runtime(seconds: f64) -> String {
    if seconds < 1.0 {
        // Less than 1 second → show milliseconds
        format!("{:.0} ms", seconds * 1000.0)
    } else {
        // 1 second or more → show seconds
        format!("{:.2} s", seconds)
    }
}
