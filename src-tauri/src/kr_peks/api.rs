use tauri::command;
use crate::kr_peks::params::Params;
use crate::kr_peks::private_key::PrivateKey;
use crate::kr_peks::public_key::PublicKey;
use crate::kr_peks::ciphertext::Ciphertext;
use crate::kr_peks::trapdoor::Trapdoor;
use crate::kr_peks::utils::*;
use super::main as krpeks_core;

use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::time::Instant;

static PARAMS: Lazy<Mutex<Option<Params>>> = Lazy::new(|| Mutex::new(None));
static PK: Lazy<Mutex<Option<PublicKey>>> = Lazy::new(|| Mutex::new(None));
static SK: Lazy<Mutex<Option<PrivateKey>>> = Lazy::new(|| Mutex::new(None));
static CIPHERTEXT: Lazy<Mutex<Option<Ciphertext>>> = Lazy::new(|| Mutex::new(None));
static TRAPDOOR: Lazy<Mutex<Option<Trapdoor>>> = Lazy::new(|| Mutex::new(None));
static TOTAL_RUNTIME: Lazy<Mutex<f64>> = Lazy::new(|| Mutex::new(0.0)); // Total computation time

#[command]
pub fn kr_peks_setup(k: usize) -> String {
    let start_time = Instant::now();

    let mut params = Params::new();
    krpeks_core::setup(&mut params, k);

    let duration = start_time.elapsed();
    *PARAMS.lock().unwrap() = Some(params);
    *TOTAL_RUNTIME.lock().unwrap() = 0.0; // Reset runtime
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate

    let mut output = String::new();
    output.push_str("✅ KR-PEKS Setup Complete!\n\n");
    output.push_str(&PARAMS.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🔵 Setup Time: {:.2?}\n", duration));

    output
}

#[command]
pub fn kr_peks_keygen() -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    if let Some(ref params) = *params_lock {
        let mut pk = PublicKey::new();
        let mut sk = PrivateKey::new();

        krpeks_core::keygen(params, &mut pk, &mut sk);

        *PK.lock().unwrap() = Some(pk);
        *SK.lock().unwrap() = Some(sk);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate

        let mut output = String::new();
        output.push_str("✅ KR-PEKS Keygen Complete!\n\n");
        output.push_str("🔒 Private Key:\n");
        output.push_str(&SK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str("\n\n🔑 Public Key:\n");
        output.push_str(&PK.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str(&format!("\n🟢 Keygen Time: {:.2?}\n", duration));

        output
    } else {
        "❌ Error: KR-PEKS setup not done yet!".into()
    }
}

#[command]
pub fn kr_peks_encrypt(keyword: String) -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    let pk_lock = PK.lock().unwrap();

    if let (Some(ref params), Some(ref pk)) = (params_lock.as_ref(), pk_lock.as_ref()) {
        let keyword_bytes = string_to_bytes(&keyword);

        let ct = krpeks_core::peks(params, pk, &keyword_bytes);

        match ct {
            Some(ciphertext) => {
                *CIPHERTEXT.lock().unwrap() = Some(ciphertext);

                let duration = start_time.elapsed();
                *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate

                let mut output = String::new();
                output.push_str("✅ KR-PEKS Encryption Complete!\n\n");
                output.push_str("📦 Ciphertext:\n");
                output.push_str(&CIPHERTEXT.lock().unwrap().as_ref().unwrap().format_full());
                output.push_str(&format!("\n🟣 Encryption Time: {:.2?}\n", duration));

                output
            }
            None => {
                "❌ Error: Encryption failed. Invalid public key.".into()
            }
        }
    } else {
        "❌ Error: Keygen not done yet!".into()
    }
}

#[command]
pub fn kr_peks_trapdoor(keyword: String) -> String {
    let start_time = Instant::now();

    let params_lock = PARAMS.lock().unwrap();
    let pk_lock = PK.lock().unwrap();
    let sk_lock = SK.lock().unwrap();

    if let (Some(ref params), Some(ref _pk), Some(ref sk)) = (
        params_lock.as_ref(), pk_lock.as_ref(), sk_lock.as_ref()
    ) {
        let keyword_bytes = string_to_bytes(&keyword);

        let td = krpeks_core::trapdoor(params, sk, &keyword_bytes);

        *TRAPDOOR.lock().unwrap() = Some(td);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate

        let mut output = String::new();
        output.push_str("✅ KR-PEKS Trapdoor Generation Complete!\n\n");
        output.push_str("🔑 Trapdoor:\n");
        output.push_str(&TRAPDOOR.lock().unwrap().as_ref().unwrap().format_full());
        output.push_str(&format!("\n🟠 Trapdoor Time: {:.2?}\n", duration));

        output
    } else {
        "❌ Error: Keygen not done yet!".into()
    }
}

#[command]
pub fn kr_peks_test() -> String {
    let start_time = Instant::now();

    let ct_lock = CIPHERTEXT.lock().unwrap();
    let td_lock = TRAPDOOR.lock().unwrap();

    if let (Some(ref ct), Some(ref td)) = (ct_lock.as_ref(), td_lock.as_ref()) {
        let result = krpeks_core::test(ct, td);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate

        let total_runtime = *TOTAL_RUNTIME.lock().unwrap(); // fetch final total

        let mut output = String::new();
        if result {
            output.push_str("✅ KR-PEKS Test Successful!\n\n");
        } else {
            output.push_str("❌ KR-PEKS Test Failed!\n\n");
        }

        output.push_str(&format!("⚡ Test Time: {:.2?}\n", duration));
        output.push_str(&format!("🏁 Total Computation Time: {}\n", format_runtime(total_runtime)));

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