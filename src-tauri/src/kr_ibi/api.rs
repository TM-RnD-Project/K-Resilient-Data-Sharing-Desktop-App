use tauri::command;

use super::params::Params;
use super::main as kribi_core;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::time::Instant;

static PARAMS: Lazy<Mutex<Option<Params>>> = Lazy::new(|| Mutex::new(None));
static TOTAL_RUNTIME: Lazy<Mutex<f64>> = Lazy::new(|| Mutex::new(0.0));

// ✅ Add this function for smart unit formatting
fn format_runtime(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else {
        format!("{:.2} s", seconds)
    }
}

#[command]
pub fn kr_ibi_setup(k: usize) -> String {
    let start_time = Instant::now();

    let mut params = Params::new();
    kribi_core::setup(&mut params, k);

    let duration = start_time.elapsed();
    *PARAMS.lock().unwrap() = Some(params);
    *TOTAL_RUNTIME.lock().unwrap() = 0.0; // Reset total runtime
    *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate setup time

    let mut output = String::new();
    output.push_str("✅ KR-IBI Setup Complete!\n\n");
    output.push_str(&PARAMS.lock().unwrap().as_ref().unwrap().format_full());
    output.push_str(&format!("\n🔵 Setup Time: {}\n", format_runtime(duration.as_secs_f64())));

    output
}

#[command]
pub fn kr_ibi_extract(id: String) -> String {
    let start_time = Instant::now();

    let params_guard = PARAMS.lock().unwrap();
    if let Some(ref params) = *params_guard {
        let id_bytes = kribi_core::string_to_bytes(&id);

        let (f1, f2) = kribi_core::extract(params, &id_bytes);

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate extract time

        format!(
            "✅ KR-IBI Private Key Extracted:\n\nf(ID1): {}\nf(ID2): {}\n\n🟢 Extract Time: {}",
            kribi_core::big_to_hex(&f1),
            kribi_core::big_to_hex(&f2),
            format_runtime(duration.as_secs_f64())
        )
    } else {
        "❌ Error: KR-IBI setup not done yet!".into()
    }
}

#[command]
pub fn kr_ibi_sign(id: String) -> String {
    let start_time = Instant::now();

    let params_guard = PARAMS.lock().unwrap();
    if let Some(ref params) = *params_guard {
        let id_bytes = kribi_core::string_to_bytes(&id);

        let (fID1, fID2) = kribi_core::extract(params, &id_bytes);

        let mut rng = kribi_core::gen_seed();
        let (g_r, r) = kribi_core::commit(params, &mut rng);
        let (c1, c2) = kribi_core::challenge(params, &mut rng);

        let (s1, s2) = kribi_core::respond(&r, &(c1, c2), &(fID1, fID2), params.get_order());

        let duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += duration.as_secs_f64(); // accumulate sign time

        format!(
            "✅ KR-IBI Signature Generated:\n\nCommit: ({}, {})\nChallenge: ({}, {})\nResponse: ({}, {})\n\n🟣 Sign Time: {}",
            kribi_core::ecp_to_hex(&g_r.0),
            kribi_core::ecp_to_hex(&g_r.1),
            kribi_core::big_to_hex(&c1),
            kribi_core::big_to_hex(&c2),
            kribi_core::big_to_hex(&s1),
            kribi_core::big_to_hex(&s2),
            format_runtime(duration.as_secs_f64())
        )
    } else {
        "❌ Error: KR-IBI setup not done yet!".into()
    }
}

#[command]
pub fn kr_ibi_verify(id: String) -> String {
    let start_time = Instant::now();

    let params_guard = PARAMS.lock().unwrap();
    if let Some(ref params) = *params_guard {
        let id_bytes = kribi_core::string_to_bytes(&id);

        let (fID1, fID2) = kribi_core::extract(params, &id_bytes);

        let mut rng = kribi_core::gen_seed();
        let (g_r, r) = kribi_core::commit(params, &mut rng);
        let (c1, c2) = kribi_core::challenge(params, &mut rng);

        let (s1, s2) = kribi_core::respond(&r, &(c1, c2), &(fID1, fID2), params.get_order());

        let valid = kribi_core::verify(params, &g_r, &(s1, s2), &(c1, c2), &id_bytes);

        let verify_duration = start_time.elapsed();
        *TOTAL_RUNTIME.lock().unwrap() += verify_duration.as_secs_f64(); // accumulate verify time

        let total_runtime = *TOTAL_RUNTIME.lock().unwrap(); // get full total runtime

        if valid {
            format!(
                "✅ KR-IBI Verification Successful!\n\n🟠 Verify Time: {}\n🏁 Total Computation Time: {}",
                format_runtime(verify_duration.as_secs_f64()),
                format_runtime(total_runtime)
            )
        } else {
            format!(
                "❌ KR-IBI Verification Failed!\n\n🟠 Verify Time: {}\n🏁 Total Computation Time: {}",
                format_runtime(verify_duration.as_secs_f64()),
                format_runtime(total_runtime)
            )
        }
    } else {
        "❌ Error: KR-IBI setup not done yet!".into()
    }
}
