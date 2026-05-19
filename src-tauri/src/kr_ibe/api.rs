use super::ciphertext::Ciphertext;
use super::main as kribe_core;
use super::params::Params;
use super::plaintext::Plaintext;
use super::private_key::PrivateKey;

use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::Instant;

static PARAMS: Lazy<Mutex<Option<Params>>> = Lazy::new(|| Mutex::new(None));
static SK: Lazy<Mutex<Option<PrivateKey>>> = Lazy::new(|| Mutex::new(None));
static CT: Lazy<Mutex<Option<Ciphertext>>> = Lazy::new(|| Mutex::new(None));
static PT: Lazy<Mutex<Option<Plaintext>>> = Lazy::new(|| Mutex::new(None));
static TOTAL_RUNTIME: Lazy<Mutex<f64>> = Lazy::new(|| Mutex::new(0.0)); // Total sum in seconds

#[tauri::command]
pub fn kr_ibe_setup(k: usize) -> String {
    let start_time = Instant::now();

    let mut params = Params::new();
    kribe_core::setup(&mut params, k);

    let duration = start_time.elapsed();
    *PARAMS.lock().unwrap() = Some(params);
    *TOTAL_RUNTIME.lock().unwrap() = 0.0; // Reset total runtime when setup new
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate setup time

    let mut output = String::new();
    output.push_str("✅ KR-IBE Setup Complete!\n\n");
    output.push_str(&PARAMS.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🔵 Setup Time: {:.2?}\n", duration));

    output
}

#[tauri::command]
pub fn kr_ibe_extract(id: String) -> String {
    let start_time = Instant::now();

    let id_bytes = id.into_bytes();
    let maybe_params = PARAMS.lock().unwrap();
    if maybe_params.is_none() {
        return "❌ Params not initialized. Please run setup first.".into();
    }

    let params = maybe_params.as_ref().unwrap();
    let mut sk = PrivateKey::new();

    kribe_core::extract(params, &mut sk, &id_bytes);

    let duration = start_time.elapsed();
    *SK.lock().unwrap() = Some(sk);
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate extract time

    let mut output = String::new();
    output.push_str("✅ Private Key Extracted.\n\n");
    output.push_str(&SK.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🟢 Extract Time: {:.2?}\n", duration));

    output
}

#[tauri::command]
pub fn kr_ibe_encrypt(id: String, plaintext: String) -> String {
    let start_time = Instant::now();

    let id_bytes = id.into_bytes();
    let msg_bytes = plaintext.into_bytes();

    let maybe_params = PARAMS.lock().unwrap();
    if maybe_params.is_none() {
        return "❌ Params not initialized. Please run setup first.".into();
    }

    let params = maybe_params.as_ref().unwrap();
    let mut ciphertext = Ciphertext::new();

    kribe_core::encryption(params, &mut ciphertext, &id_bytes, &msg_bytes);

    let duration = start_time.elapsed();
    *CT.lock().unwrap() = Some(ciphertext);
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate encryption time

    let mut output = String::new();
    output.push_str("✅ Encryption Completed.\n\n");
    output.push_str(&CT.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🟣 Encryption Time: {:.2?}\n", duration));

    output
}

#[tauri::command]
pub fn kr_ibe_decrypt() -> String {
    let start_time = Instant::now();

    let mut pt = Plaintext::new();
    {
        let mut pt_lock = PT.lock().unwrap();

        let params_guard = PARAMS.lock().unwrap();
        let sk_guard = SK.lock().unwrap();
        let mut ct_guard = CT.lock().unwrap();

        if params_guard.is_none() || sk_guard.is_none() || ct_guard.is_none() {
            return "❌ Missing data. Please run setup, extract, and encrypt first.".into();
        }

        let params = params_guard.as_ref().unwrap();
        let sk = sk_guard.as_ref().unwrap();
        let ct = ct_guard.as_mut().unwrap();

        kribe_core::decryption(params, sk, ct, &mut pt);

        *pt_lock = Some(pt);
    }

    let decryption_duration = start_time.elapsed();
    *TOTAL_RUNTIME.lock().unwrap() += decryption_duration.as_secs_f64(); // accumulate decryption time

    let pt_read = PT.lock().unwrap();
    let total_runtime = *TOTAL_RUNTIME.lock().unwrap(); // sum total

    let mut output = String::new();
    output.push_str("✅ Decryption Completed.\n\n");
    output.push_str(&pt_read.as_ref().unwrap().format_full());
    output.push_str(&format!(
        "\n🟠 Decryption Time: {:.2?}\n",
        decryption_duration
    ));
    output.push_str(&format!(
        "🏁 Total Computation Time: {}\n",
        format_runtime(total_runtime)
    ));

    output
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
