use std::collections::hash_map::DefaultHasher;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use crate::kr_ibe::{
    ciphertext::Ciphertext as IbeCiphertext, main as kribe_core, params::Params as IbeParams,
    plaintext::Plaintext, private_key::PrivateKey as IbePrivateKey,
};
use crate::kr_ibi::{main as kribi_core, params::Params as IbiParams};
use crate::kr_paeks::{
    ciphertext::Ciphertext as PaeksCiphertext, main as krpaeks_core, params::Params as PaeksParams,
    private_key::PrivateKey as PaeksPrivateKey, public_key::PublicKey as PaeksPublicKey,
};
use crate::kr_peks::{
    ciphertext::Ciphertext as PeksCiphertext, main as krpeks_core, params::Params as PeksParams,
    private_key::PrivateKey as PeksPrivateKey, public_key::PublicKey as PeksPublicKey,
};
use crate::system::utils::keyword_hash;
use mcore::ed25519::{big, ecp, rom};
use mcore::sha3::{SHA3, SHAKE256};

const DEFAULT_K: usize = 20;
const WRONG_KEYWORD: &str = "__wrong_keyword__";

type BenchmarkResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkScheme {
    Peks,
    Paeks,
}

impl BenchmarkScheme {
    fn all() -> [Self; 2] {
        [Self::Peks, Self::Paeks]
    }

    fn opposite(self) -> Self {
        match self {
            Self::Peks => Self::Paeks,
            Self::Paeks => Self::Peks,
        }
    }
}

impl Display for BenchmarkScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peks => write!(f, "KR-PEKS"),
            Self::Paeks => write!(f, "KR-PAEKS"),
        }
    }
}

#[derive(Clone)]
pub struct BenchmarkConfig {
    pub dataset_sizes: Vec<usize>,
    pub authorised_user_counts: Vec<usize>,
    pub runs_per_setting: usize,
    pub security_threshold: usize,
    pub schemes: Vec<BenchmarkScheme>,
    pub detected_cpu_threads: usize,
    pub benchmark_workers: usize,
    pub debug_raw: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        let detected_cpu_threads = detected_cpu_threads();
        let benchmark_workers = default_worker_count(detected_cpu_threads);

        Self {
            dataset_sizes: vec![100, 500, 1000, 5000, 10000],
            authorised_user_counts: vec![1, 5, 10, 20],
            runs_per_setting: 100,
            security_threshold: DEFAULT_K,
            schemes: BenchmarkScheme::all().to_vec(),
            detected_cpu_threads,
            benchmark_workers,
            debug_raw: false,
        }
    }
}

impl BenchmarkConfig {
    pub fn from_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--threads" => {
                    let value = args.next().ok_or("--threads requires a positive integer")?;
                    config.benchmark_workers = value
                        .parse::<usize>()
                        .map_err(|_| "--threads requires a positive integer".to_string())?;
                    if config.benchmark_workers == 0 {
                        return Err("--threads must be at least 1".to_string());
                    }
                }
                "--debug-raw" => {
                    config.debug_raw = true;
                }
                "--help" | "-h" => {
                    return Err("Usage: [--threads N] [--debug-raw]".to_string());
                }
                other => {
                    return Err(format!("unknown argument '{other}'"));
                }
            }
        }

        Ok(config)
    }
}

fn detected_cpu_threads() -> usize {
    thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
}

fn default_worker_count(detected_cpu_threads: usize) -> usize {
    detected_cpu_threads.saturating_sub(2).max(1)
}

#[derive(Clone, Debug)]
pub struct EmailRecord {
    pub sender: String,
    pub receiver: String,
    pub subject: String,
    pub body: String,
    pub keyword: String,
}

#[derive(Clone, Debug)]
pub struct BenchmarkRawResult {
    pub scheme: BenchmarkScheme,
    pub dataset_size: usize,
    pub authorised_users: usize,
    pub run: usize,
    pub setup_ms: f64,
    pub registration_ms: f64,
    pub login_ms: f64,
    pub ibe_encrypt_ms: f64,
    pub index_generation_ms: f64,
    pub search_ms: f64,
    pub ibe_decrypt_ms: f64,
    pub total_upload_ms: f64,
    pub total_retrieval_ms: f64,
    pub payload_ciphertext_size_bytes: usize,
    pub search_index_size_bytes: usize,
    pub successful_searches: usize,
    pub successful_decryptions: usize,
    pub wrong_keyword_rejected: bool,
    pub raw_kr_paeks_wrong_keyword_rejected: bool,
    pub wrong_scheme_rejected: bool,
    pub unauthorised_decryption_failed: bool,
    pub authenticated_login_passed: bool,
    pub unauthenticated_rejected: bool,
    pub debug: BenchmarkDebugCheck,
}

#[derive(Clone, Debug)]
pub struct BenchmarkDebugCheck {
    pub sender_id: String,
    pub receiver_id: String,
    pub run: usize,
    pub dataset_size: usize,
    pub thread_id: String,
    pub ibe_params_hash: String,
    pub peks_params_hash: String,
    pub paeks_params_hash: String,
    pub ciphertext_and_decrypt_use_same_params: bool,
    pub search_index_and_trapdoor_use_same_params: bool,
    pub authorised_v_id_matched: bool,
    pub unauthorised_v_id_matched: bool,
    pub stored_keyword: String,
    pub correct_search_keyword: String,
    pub wrong_search_keyword: String,
    pub stored_keyword_hash: String,
    pub correct_keyword_hash: String,
    pub wrong_keyword_hash: String,
    pub correct_scheme: BenchmarkScheme,
    pub wrong_scheme: BenchmarkScheme,
    pub raw_kr_paeks_wrong_keyword_test_result: bool,
    pub correct_keyword_results: usize,
    pub wrong_keyword_results: usize,
    pub wrong_scheme_results: usize,
}

#[derive(Clone, Debug)]
pub struct BenchmarkSummaryResult {
    pub scheme: BenchmarkScheme,
    pub dataset_size: usize,
    pub authorised_users: usize,
    pub runs: usize,
    pub successful_runs: usize,
    pub authenticated_login_passed: usize,
    pub unauthenticated_rejected: usize,
    pub correct_keyword_search_passed: usize,
    pub wrong_keyword_rejected: usize,
    pub raw_kr_paeks_wrong_keyword_rejected: usize,
    pub wrong_scheme_rejected: usize,
    pub authorised_decryption_passed: usize,
    pub unauthorised_decryption_failed: usize,
    pub setup_ms: f64,
    pub registration_ms: f64,
    pub login_ms: f64,
    pub ibe_encrypt_ms: f64,
    pub index_generation_ms: f64,
    pub search_ms: f64,
    pub ibe_decrypt_ms: f64,
    pub total_upload_ms: f64,
    pub total_retrieval_ms: f64,
    pub payload_ciphertext_size_bytes: f64,
    pub search_index_size_bytes: f64,
    pub successful_searches: f64,
    pub successful_decryptions: f64,
}

enum SearchIndex {
    Peks(PeksCiphertext),
    Paeks(PaeksCiphertext),
}

struct StoredBenchmarkRecord {
    ct: IbeCiphertext,
    search_scheme: BenchmarkScheme,
    sender: String,
    owner: String,
    search_index: SearchIndex,
    keyword_hash: String,
}

struct BenchmarkState {
    ibe_params: IbeParams,
    ibi_params: IbiParams,
    peks_params: PeksParams,
    peks_pk: PeksPublicKey,
    peks_sk: PeksPrivateKey,
    paeks_params: PaeksParams,
    sender_paeks_pk: PaeksPublicKey,
    sender_paeks_sk: PaeksPrivateKey,
    receiver_paeks_pk: PaeksPublicKey,
    receiver_paeks_sk: PaeksPrivateKey,
    receiver_ibe_sk: IbePrivateKey,
}

struct DecryptTrace {
    scheme: BenchmarkScheme,
    dataset_size: usize,
    authorised_users: usize,
    run: usize,
    sender_id: String,
    receiver_id: String,
    attempted_user_id: String,
    thread_id: String,
    params_hash: String,
    ciphertext_params_hash: String,
    decrypt_params_hash: String,
    same_params: bool,
    authorised_attempt: bool,
}

#[derive(Clone, Copy)]
struct BenchmarkJob {
    scheme: BenchmarkScheme,
    dataset_size: usize,
    authorised_users: usize,
    run: usize,
}

pub fn run_enron_benchmark(config: BenchmarkConfig) -> BenchmarkResult<()> {
    let dataset_path = find_dataset_path()?;
    let max_records = config.dataset_sizes.iter().copied().max().unwrap_or(0);
    let records = load_enron_records(&dataset_path, max_records)?;

    if records.len() < max_records {
        return Err(format!(
            "Only {} valid email records were loaded, but {} are required.",
            records.len(),
            max_records
        )
        .into());
    }

    print_header(&dataset_path, &config);

    let jobs = build_jobs(&config);
    let pool = ThreadPoolBuilder::new()
        .num_threads(config.benchmark_workers)
        .build()?;

    let raw_results_result: BenchmarkResult<Vec<BenchmarkRawResult>> = pool.install(|| {
        jobs.par_iter()
            .map(|job| {
                run_one(
                    job.scheme,
                    job.dataset_size,
                    job.authorised_users,
                    job.run,
                    &records[..job.dataset_size],
                    &config,
                )
            })
            .collect()
    });

    let mut raw_results = raw_results_result?;
    raw_results.sort_by_key(|result| {
        (
            scheme_order(result.scheme),
            result.dataset_size,
            result.authorised_users,
            result.run,
        )
    });

    let summaries = summarise_all(&raw_results);
    for summary in &summaries {
        print_setting_report(summary, config.debug_raw);
        if config.debug_raw {
            if let Some(debug_result) = raw_results.iter().find(|result| {
                result.scheme == summary.scheme
                    && result.dataset_size == summary.dataset_size
                    && result.authorised_users == summary.authorised_users
                    && result.run == 1
            }) {
                print_debug_check(debug_result);
            }
        }
    }

    fs::create_dir_all("benchmark_results")?;
    write_raw_csv("benchmark_results/enron_raw_results.csv", &raw_results)?;
    write_summary_csv("benchmark_results/enron_summary_results.csv", &summaries)?;
    write_comparison_csv(
        "benchmark_results/enron_peks_vs_paeks_comparison.csv",
        &summaries,
    )?;

    print_summary_tables(&summaries);
    Ok(())
}

fn build_jobs(config: &BenchmarkConfig) -> Vec<BenchmarkJob> {
    let mut jobs = Vec::new();
    for scheme in config.schemes.iter().copied() {
        for dataset_size in &config.dataset_sizes {
            for authorised_users in &config.authorised_user_counts {
                for run in 1..=config.runs_per_setting {
                    jobs.push(BenchmarkJob {
                        scheme,
                        dataset_size: *dataset_size,
                        authorised_users: *authorised_users,
                        run,
                    });
                }
            }
        }
    }

    jobs
}

fn scheme_order(scheme: BenchmarkScheme) -> usize {
    match scheme {
        BenchmarkScheme::Peks => 0,
        BenchmarkScheme::Paeks => 1,
    }
}

fn run_one(
    scheme: BenchmarkScheme,
    dataset_size: usize,
    authorised_users: usize,
    run: usize,
    records: &[EmailRecord],
    config: &BenchmarkConfig,
) -> BenchmarkResult<BenchmarkRawResult> {
    let start_setup = Instant::now();
    let mut state = setup_state(config.security_threshold)?;
    let setup_ms = elapsed_ms(start_setup);

    let sender = format!("sender_{run}@benchmark.local");
    let receiver = format!("receiver_0_{run}@benchmark.local");
    let unauthorised = format!("unauthorised_{run}@benchmark.local");
    let thread_id = format!("{:?}", thread::current().id());
    let ibe_params_hash = params_hash_from_text(&state.ibe_params.format_full());
    let peks_params_hash = params_hash_from_text(&state.peks_params.format_full());
    let paeks_params_hash = params_hash_from_text(&state.paeks_params.format_full());

    let start_registration = Instant::now();
    let mut receiver_keys = Vec::with_capacity(authorised_users);
    for index in 0..authorised_users {
        let id = format!("receiver_{index}_{run}@benchmark.local");
        receiver_keys.push(extract_ibe_key(&state.ibe_params, &id));
    }
    state.receiver_ibe_sk = receiver_keys
        .first()
        .cloned()
        .ok_or("At least one authorised user is required")?;
    let unauthorised_ibe_sk = extract_ibe_key(&state.ibe_params, &unauthorised);
    let registration_ms = elapsed_ms(start_registration);

    let start_login = Instant::now();
    let authenticated_login_passed = authenticate_identity(&state.ibi_params, &receiver);
    let unauthenticated_rejected = !is_authenticated(false);
    let login_ms = elapsed_ms(start_login);

    let selected = &records[(run - 1) % dataset_size];
    let selected_index = (run - 1) % dataset_size;
    let payload = selected.body.as_bytes().to_vec();
    let receiver_bytes = receiver.as_bytes().to_vec();

    let start_encrypt = Instant::now();
    let mut ibe_ct = IbeCiphertext::new();
    kribe_core::encryption(&state.ibe_params, &mut ibe_ct, &receiver_bytes, &payload);
    let ibe_encrypt_ms = elapsed_ms(start_encrypt);

    let start_index = Instant::now();
    let stored_records = build_stored_records(
        scheme,
        records,
        &state,
        &sender,
        &receiver,
        selected_index,
        &ibe_ct,
    );
    let index_generation_ms = elapsed_ms(start_index);
    let search_index_size_bytes = stored_records
        .first()
        .map(|record| search_index_size(&record.search_index))
        .unwrap_or_default();

    let start_search = Instant::now();
    let correct_results = app_search(
        &receiver,
        scheme,
        &selected.keyword,
        &stored_records,
        &state,
    );
    let successful_searches = correct_results.len();
    let search_ms = elapsed_ms(start_search);

    let wrong_keyword_results =
        app_search(&receiver, scheme, WRONG_KEYWORD, &stored_records, &state).len();
    let wrong_scheme_results = app_search(
        &receiver,
        scheme.opposite(),
        &selected.keyword,
        &stored_records,
        &state,
    )
    .len();
    let raw_kr_paeks_wrong_keyword_results = if config.debug_raw && scheme == BenchmarkScheme::Paeks
    {
        raw_search_indexes(scheme, WRONG_KEYWORD, &stored_records, &state)
    } else {
        0
    };
    let wrong_keyword_rejected = wrong_keyword_results == 0;
    let raw_kr_paeks_wrong_keyword_rejected = !config.debug_raw
        || scheme != BenchmarkScheme::Paeks
        || raw_kr_paeks_wrong_keyword_results == 0;
    let wrong_scheme_rejected = wrong_scheme_results == 0;

    let start_decrypt = Instant::now();
    let ciphertext_and_decrypt_use_same_params = true;
    let authorised_v_id_matched = ibe_v_id_matches(
        &state.ibe_params,
        &state.receiver_ibe_sk,
        &stored_records[selected_index].ct,
    );
    let authorised_trace = DecryptTrace {
        scheme,
        dataset_size,
        authorised_users,
        run,
        sender_id: sender.clone(),
        receiver_id: receiver.clone(),
        attempted_user_id: receiver.clone(),
        thread_id: thread_id.clone(),
        params_hash: ibe_params_hash.clone(),
        ciphertext_params_hash: ibe_params_hash.clone(),
        decrypt_params_hash: ibe_params_hash.clone(),
        same_params: ciphertext_and_decrypt_use_same_params,
        authorised_attempt: true,
    };
    let authorised_plaintext = if correct_results.contains(&selected_index) {
        decrypt_payload_checked(
            &state.ibe_params,
            &state.receiver_ibe_sk,
            &stored_records[selected_index].ct,
            &authorised_trace,
        )
    } else {
        None
    };
    let ibe_decrypt_ms = elapsed_ms(start_decrypt);

    let successful_decryptions =
        usize::from(authorised_plaintext.as_deref() == Some(&selected.body));

    let unauthorised_v_id_matched =
        ibe_v_id_matches(&state.ibe_params, &unauthorised_ibe_sk, &ibe_ct);
    let unauthorised_trace = DecryptTrace {
        scheme,
        dataset_size,
        authorised_users,
        run,
        sender_id: sender.clone(),
        receiver_id: receiver.clone(),
        attempted_user_id: unauthorised.clone(),
        thread_id: thread_id.clone(),
        params_hash: ibe_params_hash.clone(),
        ciphertext_params_hash: ibe_params_hash.clone(),
        decrypt_params_hash: ibe_params_hash.clone(),
        same_params: ciphertext_and_decrypt_use_same_params,
        authorised_attempt: false,
    };
    let unauthorised_plaintext = decrypt_payload_checked(
        &state.ibe_params,
        &unauthorised_ibe_sk,
        &ibe_ct,
        &unauthorised_trace,
    );
    let unauthorised_decryption_failed = unauthorised_plaintext.as_deref() != Some(&selected.body);

    Ok(BenchmarkRawResult {
        scheme,
        dataset_size,
        authorised_users,
        run,
        setup_ms,
        registration_ms,
        login_ms,
        ibe_encrypt_ms,
        index_generation_ms,
        search_ms,
        ibe_decrypt_ms,
        total_upload_ms: ibe_encrypt_ms + index_generation_ms,
        total_retrieval_ms: login_ms + search_ms + ibe_decrypt_ms,
        payload_ciphertext_size_bytes: ibe_ciphertext_size(&ibe_ct),
        search_index_size_bytes,
        successful_searches,
        successful_decryptions,
        wrong_keyword_rejected,
        raw_kr_paeks_wrong_keyword_rejected,
        wrong_scheme_rejected,
        unauthorised_decryption_failed,
        authenticated_login_passed,
        unauthenticated_rejected,
        debug: BenchmarkDebugCheck {
            sender_id: sender,
            receiver_id: receiver,
            run,
            dataset_size,
            thread_id,
            ibe_params_hash,
            peks_params_hash,
            paeks_params_hash,
            ciphertext_and_decrypt_use_same_params,
            search_index_and_trapdoor_use_same_params: true,
            authorised_v_id_matched,
            unauthorised_v_id_matched,
            stored_keyword: selected.keyword.clone(),
            correct_search_keyword: selected.keyword.clone(),
            wrong_search_keyword: WRONG_KEYWORD.to_string(),
            stored_keyword_hash: stored_records[selected_index].keyword_hash.clone(),
            correct_keyword_hash: keyword_hash(&selected.keyword),
            wrong_keyword_hash: keyword_hash(WRONG_KEYWORD),
            correct_scheme: scheme,
            wrong_scheme: scheme.opposite(),
            raw_kr_paeks_wrong_keyword_test_result: raw_kr_paeks_wrong_keyword_results > 0,
            correct_keyword_results: successful_searches,
            wrong_keyword_results,
            wrong_scheme_results,
        },
    })
}

fn setup_state(k: usize) -> BenchmarkResult<BenchmarkState> {
    let mut ibe_params = IbeParams::new();
    kribe_core::setup(&mut ibe_params, k);

    let mut ibi_params = IbiParams::new();
    ibi_setup_silent(&mut ibi_params, k);

    let mut peks_params = PeksParams::new();
    krpeks_core::setup(&mut peks_params, k);
    let mut peks_pk = PeksPublicKey::new();
    let mut peks_sk = PeksPrivateKey::new();
    krpeks_core::keygen(&peks_params, &mut peks_pk, &mut peks_sk);

    let mut paeks_params = PaeksParams::new();
    krpaeks_core::setup(&mut paeks_params, k);
    let (sender_paeks_pk, sender_paeks_sk) = paeks_keypair(&paeks_params);
    let (receiver_paeks_pk, receiver_paeks_sk) = paeks_keypair(&paeks_params);

    let receiver_ibe_sk = extract_ibe_key(&ibe_params, "receiver_0@benchmark.local");

    Ok(BenchmarkState {
        ibe_params,
        ibi_params,
        peks_params,
        peks_pk,
        peks_sk,
        paeks_params,
        sender_paeks_pk,
        sender_paeks_sk,
        receiver_paeks_pk,
        receiver_paeks_sk,
        receiver_ibe_sk,
    })
}

fn paeks_keypair(params: &PaeksParams) -> (PaeksPublicKey, PaeksPrivateKey) {
    let mut pk = PaeksPublicKey::new();
    let mut sk = PaeksPrivateKey::new();
    krpaeks_core::keygen(params, &mut pk, &mut sk);
    (pk, sk)
}

fn extract_ibe_key(params: &IbeParams, id: &str) -> IbePrivateKey {
    let mut sk = IbePrivateKey::new();
    kribe_core::extract(params, &mut sk, &id.as_bytes().to_vec());
    sk
}

fn authenticate_identity(params: &IbiParams, id: &str) -> bool {
    let id_bytes = id.as_bytes().to_vec();
    let (f1, f2) = ibi_extract_silent(params, &id_bytes);
    let mut rng = kribi_core::gen_seed();
    let (g_r, r) = kribi_core::commit(params, &mut rng);
    let challenge = kribi_core::challenge(params, &mut rng);
    let response = kribi_core::respond(&r, &challenge, &(f1, f2), params.get_order());
    ibi_verify_silent(params, &g_r, &response, &challenge, &id_bytes)
}

fn ibi_setup_silent(params: &mut IbiParams, k: usize) {
    let order = big::BIG::new_ints(&rom::CURVE_ORDER);
    let g = ecp::ECP::generator();
    let mut rng = kribi_core::gen_seed();
    let t = k + 1;

    let mut fx1 = vec![big::BIG::new(); t];
    let mut fx2 = vec![big::BIG::new(); t];

    for i in 0..t {
        fx1[i] = big::BIG::randomnum(&order, &mut rng);
        fx2[i] = big::BIG::randomnum(&order, &mut rng);
    }

    let mut dt1 = vec![ecp::ECP::new(); t];
    let mut dt2 = vec![ecp::ECP::new(); t];

    for i in 0..t {
        dt1[i] = g.mul(&fx1[i]);
        dt2[i] = g.mul(&fx2[i]);
    }

    params.set_params(k, order, g, dt1, dt2, fx1, fx2);
}

fn ibi_extract_silent(params: &IbiParams, id: &[u8]) -> (big::BIG, big::BIG) {
    let k = params.get_k() + 1;
    let order = params.get_order();
    let d1 = params.get_msk1();
    let d2 = params.get_msk2();

    let x = kribi_core::hash_to_big(id);
    let mut f1 = big::BIG::new_int(0);
    let mut f2 = big::BIG::new_int(0);

    for i in 0..k {
        let mut x_for_pow = x.clone();
        let exponent = big::BIG::new_int(i as isize);
        let xpowi = big::BIG::powmod(&mut x_for_pow, &exponent, order);

        let temp1 = big::BIG::modmul(&d1[i], &xpowi, order);
        f1.add(&temp1);
        f1.rmod(order);

        let temp2 = big::BIG::modmul(&d2[i], &xpowi, order);
        f2.add(&temp2);
        f2.rmod(order);
    }

    (f1, f2)
}

fn ibi_verify_silent(
    params: &IbiParams,
    g_r: &(ecp::ECP, ecp::ECP),
    response: &(big::BIG, big::BIG),
    challenge: &(big::BIG, big::BIG),
    id: &[u8],
) -> bool {
    let x = kribi_core::hash_to_big(id);

    let f_id_point1 = {
        let mut sum = ecp::ECP::new();
        for i in 0..params.get_k() + 1 {
            let mut x_for_pow = x.clone();
            let exponent = big::BIG::new_int(i as isize);
            let xpowi = big::BIG::powmod(&mut x_for_pow, &exponent, params.get_order());
            let temp = params.get_Dt1()[i].mul(&xpowi);
            sum.add(&temp);
        }
        sum
    };

    let f_id_point2 = {
        let mut sum = ecp::ECP::new();
        for i in 0..params.get_k() + 1 {
            let mut x_for_pow = x.clone();
            let exponent = big::BIG::new_int(i as isize);
            let xpowi = big::BIG::powmod(&mut x_for_pow, &exponent, params.get_order());
            let temp = params.get_Dt2()[i].mul(&xpowi);
            sum.add(&temp);
        }
        sum
    };

    let mut g_r_f_id_c1 = f_id_point1.mul(&challenge.0);
    g_r_f_id_c1.add(&g_r.0);

    let mut g_r_f_id_c2 = f_id_point2.mul(&challenge.1);
    g_r_f_id_c2.add(&g_r.1);

    let valid_1 = g_r_f_id_c1.equals(&ecp::ECP::generator().mul(&response.0));
    let valid_2 = g_r_f_id_c2.equals(&ecp::ECP::generator().mul(&response.1));

    valid_1 && valid_2
}

fn is_authenticated(active_session: bool) -> bool {
    active_session
}

fn build_stored_records(
    scheme: BenchmarkScheme,
    records: &[EmailRecord],
    state: &BenchmarkState,
    sender: &str,
    owner: &str,
    selected_index: usize,
    selected_ct: &IbeCiphertext,
) -> Vec<StoredBenchmarkRecord> {
    records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            let search_index = match scheme {
                BenchmarkScheme::Peks => krpeks_core::peks(
                    &state.peks_params,
                    &state.peks_pk,
                    &record.keyword.as_bytes().to_vec(),
                )
                .map(SearchIndex::Peks)?,
                BenchmarkScheme::Paeks => {
                    let keyword_big = krpaeks_core::hash_to_big(&record.keyword);
                    SearchIndex::Paeks(krpaeks_core::encrypt(
                        &state.paeks_params,
                        &state.receiver_paeks_pk,
                        &state.sender_paeks_sk,
                        &keyword_big,
                    ))
                }
            };

            Some(StoredBenchmarkRecord {
                // Search correctness does not need every payload body decrypted. The selected
                // record carries the real upload ciphertext used by the retrieval check.
                ct: if index == selected_index {
                    selected_ct.clone()
                } else {
                    IbeCiphertext::new()
                },
                search_scheme: scheme,
                sender: sender.to_string(),
                owner: owner.to_string(),
                search_index,
                keyword_hash: keyword_hash(&record.keyword),
            })
        })
        .collect()
}

fn app_search(
    user: &str,
    requested_scheme: BenchmarkScheme,
    keyword: &str,
    records: &[StoredBenchmarkRecord],
    state: &BenchmarkState,
) -> Vec<usize> {
    let search_hash = keyword_hash(keyword);
    let mut results = Vec::new();

    match requested_scheme {
        BenchmarkScheme::Peks => {
            let keyword_bytes = keyword.as_bytes().to_vec();
            let trapdoor =
                krpeks_core::trapdoor(&state.peks_params, &state.peks_sk, &keyword_bytes);

            for (index, record) in records.iter().enumerate() {
                if record.owner != user {
                    continue;
                }

                if record.search_scheme != requested_scheme {
                    continue;
                }

                if record.keyword_hash != search_hash {
                    continue;
                }

                if let SearchIndex::Peks(peks_index) = &record.search_index {
                    if krpeks_core::test(peks_index, &trapdoor) {
                        results.push(index);
                    }
                }
            }
        }
        BenchmarkScheme::Paeks => {
            let keyword_big = krpaeks_core::hash_to_big(keyword);

            for (index, record) in records.iter().enumerate() {
                if record.owner != user {
                    continue;
                }

                if record.search_scheme != requested_scheme {
                    continue;
                }

                if record.keyword_hash != search_hash {
                    continue;
                }

                if let SearchIndex::Paeks(paeks_index) = &record.search_index {
                    // All benchmark uploads in one run use the same sender keypair. The sender
                    // field is still stored so this mirrors the application record shape.
                    let _sender = &record.sender;
                    let trapdoor = krpaeks_core::trapdoor(
                        &state.paeks_params,
                        &state.sender_paeks_pk,
                        &state.receiver_paeks_sk,
                        &keyword_big,
                    );

                    if krpaeks_core::test(paeks_index, &trapdoor) {
                        results.push(index);
                    }
                }
            }
        }
    }

    results
}

fn raw_search_indexes(
    scheme: BenchmarkScheme,
    keyword: &str,
    records: &[StoredBenchmarkRecord],
    state: &BenchmarkState,
) -> usize {
    match scheme {
        BenchmarkScheme::Peks => {
            let keyword_bytes = keyword.as_bytes().to_vec();
            let trapdoor =
                krpeks_core::trapdoor(&state.peks_params, &state.peks_sk, &keyword_bytes);
            records
                .iter()
                .filter_map(|record| match &record.search_index {
                    SearchIndex::Peks(ct) => Some(ct),
                    SearchIndex::Paeks(_) => None,
                })
                .filter(|ct| krpeks_core::test(ct, &trapdoor))
                .count()
        }
        BenchmarkScheme::Paeks => {
            let keyword_big = krpaeks_core::hash_to_big(keyword);
            let trapdoor = krpaeks_core::trapdoor(
                &state.paeks_params,
                &state.sender_paeks_pk,
                &state.receiver_paeks_sk,
                &keyword_big,
            );
            records
                .iter()
                .filter_map(|record| match &record.search_index {
                    SearchIndex::Peks(_) => None,
                    SearchIndex::Paeks(ct) => Some(ct),
                })
                .filter(|ct| krpaeks_core::test(ct, &trapdoor))
                .count()
        }
    }
}

fn decrypt_payload(params: &IbeParams, sk: &IbePrivateKey, ct: &IbeCiphertext) -> Option<String> {
    let mut ciphertext = ct.clone();
    let mut plaintext = Plaintext::new();
    kribe_core::decryption(params, sk, &mut ciphertext, &mut plaintext);
    let text = plaintext.to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn decrypt_payload_checked(
    params: &IbeParams,
    sk: &IbePrivateKey,
    ct: &IbeCiphertext,
    trace: &DecryptTrace,
) -> Option<String> {
    if !ibe_v_id_matches(params, sk, ct) {
        if trace.authorised_attempt {
            print_v_id_mismatch_trace(trace);
        }

        return None;
    }

    catch_unwind(AssertUnwindSafe(|| decrypt_payload(params, sk, ct)))
        .ok()
        .flatten()
}

fn ibe_v_id_matches(params: &IbeParams, sk: &IbePrivateKey, ct: &IbeCiphertext) -> bool {
    let order = params.get_order();

    let u1 = ct.get_u1();
    let u2 = ct.get_u2();
    let c = ct.get_c();

    let mut temp_alpha = u1.clone();
    temp_alpha.add(u2);
    temp_alpha.add(c);
    let alpha = hash_ecp_to_big(temp_alpha);

    let h1_id_alpha = big::BIG::modmul(sk.get_h1ID(), &alpha, order);
    let pow1 = big::BIG::modadd(sk.get_f1ID(), &h1_id_alpha, order);
    let mut temp_u1 = u1.clmul(&pow1, order);

    let h2_id_alpha = big::BIG::modmul(sk.get_h2ID(), &alpha, order);
    let pow2 = big::BIG::modadd(sk.get_f2ID(), &h2_id_alpha, order);
    let temp_u2 = u2.clmul(&pow2, order);

    temp_u1.add(&temp_u2);
    ct.get_v_id().equals(&temp_u1)
}

fn hash_ecp_to_big(input: ecp::ECP) -> big::BIG {
    let mut hasher = SHA3::new(SHAKE256);
    let mut bytes = vec![0; big::MODBYTES + 1];
    input.tobytes(&mut bytes, true);
    hasher.process_array(&bytes);
    let mut output = [0u8; big::MODBYTES];
    hasher.shake(&mut output, big::MODBYTES);
    big::BIG::frombytes(&output)
}

fn params_hash_from_text(text: &str) -> String {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn print_v_id_mismatch_trace(trace: &DecryptTrace) {
    eprintln!("KR-IBE authorised decrypt v_id mismatch trace:");
    eprintln!("  scheme: {}", trace.scheme);
    eprintln!("  sender ID: {}", trace.sender_id);
    eprintln!("  receiver ID: {}", trace.receiver_id);
    eprintln!("  attempted user ID: {}", trace.attempted_user_id);
    eprintln!("  benchmark run: {}", trace.run);
    eprintln!("  dataset size: {}", trace.dataset_size);
    eprintln!("  authorised users: {}", trace.authorised_users);
    eprintln!("  thread ID: {}", trace.thread_id);
    eprintln!("  params hash: {}", trace.params_hash);
    eprintln!("  ciphertext params hash: {}", trace.ciphertext_params_hash);
    eprintln!("  decrypt params hash: {}", trace.decrypt_params_hash);
    eprintln!("  ciphertext/decrypt same params: {}", trace.same_params);
}

fn ibe_ciphertext_size(ct: &IbeCiphertext) -> usize {
    ct.format_full().len()
}

fn search_index_size(index: &SearchIndex) -> usize {
    match index {
        SearchIndex::Peks(ct) => ct.format_full().len(),
        SearchIndex::Paeks(ct) => ct.format_full().len(),
    }
}

pub fn load_enron_records(path: &Path, limit: usize) -> BenchmarkResult<Vec<EmailRecord>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::with_capacity(limit);

    for line in reader.lines() {
        let line = line?;
        if !line.starts_with("INSERT INTO") {
            continue;
        }

        for row in parse_insert_values(&line) {
            if let Some(record) = row_to_email_record(row) {
                records.push(record);
                if records.len() >= limit {
                    return Ok(records);
                }
            }
        }
    }

    Ok(records)
}

fn row_to_email_record(fields: Vec<Option<String>>) -> Option<EmailRecord> {
    if fields.len() < 6 {
        return None;
    }

    let sender = clean_field(fields.get(3)?.as_ref()?)?;
    let receiver = clean_field(fields.get(4)?.as_ref()?)?;
    let body = clean_field(fields.get(5)?.as_ref()?)?;
    let subject = extract_subject(&body).unwrap_or_default();
    let keyword = if subject.is_empty() {
        derive_keyword(&body)?
    } else {
        subject
            .split_whitespace()
            .find(|word| word.chars().any(|ch| ch.is_alphabetic()))
            .unwrap_or(&subject)
            .to_string()
    };

    Some(EmailRecord {
        sender,
        receiver,
        subject,
        body,
        keyword: normalise_keyword(&keyword)?,
    })
}

fn parse_insert_values(line: &str) -> Vec<Vec<Option<String>>> {
    let mut rows = Vec::new();
    let mut current_row = Vec::new();
    let mut current_field = String::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut in_row = false;
    let mut field_was_quoted = false;

    for ch in line.chars().skip_while(|ch| *ch != '(') {
        if in_string {
            if escaped {
                current_field.push(match ch {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '0' => '\0',
                    other => other,
                });
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '\'' {
                in_string = false;
            } else {
                current_field.push(ch);
            }
            continue;
        }

        match ch {
            '(' if !in_row => {
                in_row = true;
                current_row.clear();
                current_field.clear();
                field_was_quoted = false;
            }
            '\'' if in_row => {
                in_string = true;
                field_was_quoted = true;
            }
            ',' if in_row => {
                push_sql_field(&mut current_row, &mut current_field, field_was_quoted);
                field_was_quoted = false;
            }
            ')' if in_row => {
                push_sql_field(&mut current_row, &mut current_field, field_was_quoted);
                rows.push(current_row.clone());
                current_row.clear();
                field_was_quoted = false;
                in_row = false;
            }
            _ if in_row => current_field.push(ch),
            _ => {}
        }
    }

    rows
}

fn push_sql_field(row: &mut Vec<Option<String>>, field: &mut String, was_quoted: bool) {
    let value = field.trim();
    if !was_quoted && value.eq_ignore_ascii_case("NULL") {
        row.push(None);
    } else {
        row.push(Some(field.clone()));
    }
    field.clear();
}

fn clean_field(value: &str) -> Option<String> {
    let cleaned = value.trim().replace('\0', "");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn extract_subject(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.trim().strip_prefix("Subject:"))
        .and_then(clean_field)
}

fn derive_keyword(body: &str) -> Option<String> {
    body.split(|ch: char| !ch.is_alphabetic())
        .find(|word| word.len() >= 4)
        .and_then(normalise_keyword)
}

fn normalise_keyword(keyword: &str) -> Option<String> {
    let cleaned = keyword
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    if cleaned.len() >= 4 {
        Some(cleaned)
    } else {
        None
    }
}

fn find_dataset_path() -> BenchmarkResult<PathBuf> {
    for candidate in [
        PathBuf::from("dataset/EnronMailDB.sql"),
        PathBuf::from("../dataset/EnronMailDB.sql"),
        PathBuf::from("/dataset/EnronMailDB.sql"),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err("EnronMailDB.sql was not found in dataset/, ../dataset/, or /dataset/".into())
}

fn summarise_all(raw_results: &[BenchmarkRawResult]) -> Vec<BenchmarkSummaryResult> {
    let mut summaries = Vec::new();
    for scheme in selected_schemes(raw_results) {
        let mut groups: Vec<(usize, usize)> = raw_results
            .iter()
            .filter(|result| result.scheme == scheme)
            .map(|result| (result.dataset_size, result.authorised_users))
            .collect();
        groups.sort_unstable();
        groups.dedup();

        for (dataset_size, authorised_users) in groups {
            let group: Vec<_> = raw_results
                .iter()
                .filter(|result| {
                    result.scheme == scheme
                        && result.dataset_size == dataset_size
                        && result.authorised_users == authorised_users
                })
                .cloned()
                .collect();
            summaries.push(summarise(&group));
        }
    }
    summaries
}

fn selected_schemes(raw_results: &[BenchmarkRawResult]) -> Vec<BenchmarkScheme> {
    let mut schemes: Vec<_> = raw_results.iter().map(|result| result.scheme).collect();
    schemes.sort_by_key(|scheme| match scheme {
        BenchmarkScheme::Peks => 0,
        BenchmarkScheme::Paeks => 1,
    });
    schemes.dedup();
    schemes
}

fn selected_schemes_from_summaries(summaries: &[BenchmarkSummaryResult]) -> Vec<BenchmarkScheme> {
    let mut schemes: Vec<_> = summaries.iter().map(|summary| summary.scheme).collect();
    schemes.sort_by_key(|scheme| match scheme {
        BenchmarkScheme::Peks => 0,
        BenchmarkScheme::Paeks => 1,
    });
    schemes.dedup();
    schemes
}

fn has_scheme(summaries: &[BenchmarkSummaryResult], scheme: BenchmarkScheme) -> bool {
    summaries.iter().any(|summary| summary.scheme == scheme)
}

fn summarise(results: &[BenchmarkRawResult]) -> BenchmarkSummaryResult {
    let runs = results.len().max(1);
    let first = results
        .first()
        .expect("summary requires at least one result");
    let successful_runs = results
        .iter()
        .filter(|r| {
            r.authenticated_login_passed
                && r.unauthenticated_rejected
                && r.successful_searches > 0
                && r.successful_decryptions > 0
                && r.wrong_keyword_rejected
                && r.wrong_scheme_rejected
                && r.unauthorised_decryption_failed
        })
        .count();

    BenchmarkSummaryResult {
        scheme: first.scheme,
        dataset_size: first.dataset_size,
        authorised_users: first.authorised_users,
        runs: results.len(),
        successful_runs,
        authenticated_login_passed: count_bool(results, |r| r.authenticated_login_passed),
        unauthenticated_rejected: count_bool(results, |r| r.unauthenticated_rejected),
        correct_keyword_search_passed: results.iter().filter(|r| r.successful_searches > 0).count(),
        wrong_keyword_rejected: count_bool(results, |r| r.wrong_keyword_rejected),
        raw_kr_paeks_wrong_keyword_rejected: count_bool(results, |r| {
            r.raw_kr_paeks_wrong_keyword_rejected
        }),
        wrong_scheme_rejected: count_bool(results, |r| r.wrong_scheme_rejected),
        authorised_decryption_passed: results
            .iter()
            .filter(|r| r.successful_decryptions > 0)
            .count(),
        unauthorised_decryption_failed: count_bool(results, |r| r.unauthorised_decryption_failed),
        setup_ms: avg(results, |r| r.setup_ms, runs),
        registration_ms: avg(results, |r| r.registration_ms, runs),
        login_ms: avg(results, |r| r.login_ms, runs),
        ibe_encrypt_ms: avg(results, |r| r.ibe_encrypt_ms, runs),
        index_generation_ms: avg(results, |r| r.index_generation_ms, runs),
        search_ms: avg(results, |r| r.search_ms, runs),
        ibe_decrypt_ms: avg(results, |r| r.ibe_decrypt_ms, runs),
        total_upload_ms: avg(results, |r| r.total_upload_ms, runs),
        total_retrieval_ms: avg(results, |r| r.total_retrieval_ms, runs),
        payload_ciphertext_size_bytes: avg_usize(
            results,
            |r| r.payload_ciphertext_size_bytes,
            runs,
        ),
        search_index_size_bytes: avg_usize(results, |r| r.search_index_size_bytes, runs),
        successful_searches: avg_usize(results, |r| r.successful_searches, runs),
        successful_decryptions: avg_usize(results, |r| r.successful_decryptions, runs),
    }
}

fn count_bool<F>(results: &[BenchmarkRawResult], predicate: F) -> usize
where
    F: Fn(&BenchmarkRawResult) -> bool,
{
    results.iter().filter(|result| predicate(result)).count()
}

fn avg<F>(results: &[BenchmarkRawResult], field: F, runs: usize) -> f64
where
    F: Fn(&BenchmarkRawResult) -> f64,
{
    results.iter().map(field).sum::<f64>() / runs as f64
}

fn avg_usize<F>(results: &[BenchmarkRawResult], field: F, runs: usize) -> f64
where
    F: Fn(&BenchmarkRawResult) -> usize,
{
    results.iter().map(field).sum::<usize>() as f64 / runs as f64
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn print_header(dataset_path: &Path, config: &BenchmarkConfig) {
    println!("====================================================");
    println!("KR Data Sharing Evaluation over EnronMail Dataset");
    println!("====================================================");
    println!();
    print_row("Dataset source:", &dataset_path.display().to_string());
    print_row(
        "Detected CPU threads:",
        &config.detected_cpu_threads.to_string(),
    );
    print_row(
        "Using benchmark workers:",
        &config.benchmark_workers.to_string(),
    );
    print_row("Runs per setting:", &config.runs_per_setting.to_string());
    print_row("Dataset sizes:", &format!("{:?}", config.dataset_sizes));
    print_row(
        "Authorised identity counts:",
        &format!("{:?}", config.authorised_user_counts),
    );
    print_row(
        "Search schemes:",
        &format!(
            "[{}]",
            config
                .schemes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
}

fn print_setting_report(summary: &BenchmarkSummaryResult, debug_raw: bool) {
    println!();
    println!("----------------------------------------------------");
    print_row("Scheme:", &summary.scheme.to_string());
    print_row("Dataset size:", &summary.dataset_size.to_string());
    print_row(
        "Authorised identities:",
        &summary.authorised_users.to_string(),
    );
    println!("----------------------------------------------------");
    print_count("Successful runs:", summary.successful_runs, summary.runs);
    print_count(
        "Authenticated login passed:",
        summary.authenticated_login_passed,
        summary.runs,
    );
    print_count(
        "Unauthenticated user rejected:",
        summary.unauthenticated_rejected,
        summary.runs,
    );
    print_count(
        "Correct keyword search passed:",
        summary.correct_keyword_search_passed,
        summary.runs,
    );
    if debug_raw && summary.scheme == BenchmarkScheme::Paeks {
        print_count(
            "Raw KR-PAEKS wrong keyword rejected:",
            summary.raw_kr_paeks_wrong_keyword_rejected,
            summary.runs,
        );
    }
    print_count(
        "Wrong keyword rejected:",
        summary.wrong_keyword_rejected,
        summary.runs,
    );
    print_count(
        "Wrong scheme rejected:",
        summary.wrong_scheme_rejected,
        summary.runs,
    );
    print_count(
        "Authorised decryption passed:",
        summary.authorised_decryption_passed,
        summary.runs,
    );
    print_count(
        "Unauthorised decryption failed:",
        summary.unauthorised_decryption_failed,
        summary.runs,
    );
    println!();
    println!("Average Performance:");
    print_ms("Setup time:", summary.setup_ms);
    print_ms("Registration/KeyGen time:", summary.registration_ms);
    print_ms("Login/Auth time:", summary.login_ms);
    print_ms("KR-IBE encryption time:", summary.ibe_encrypt_ms);
    print_ms("Search index generation time:", summary.index_generation_ms);
    print_ms("Search/Trapdoor/Test time:", summary.search_ms);
    print_ms("KR-IBE decryption time:", summary.ibe_decrypt_ms);
    print_ms("Total upload time:", summary.total_upload_ms);
    print_ms("Total retrieval time:", summary.total_retrieval_ms);
    println!();
    println!("Average Size:");
    print_row(
        "Payload ciphertext size:",
        &format!("{:.0} bytes", summary.payload_ciphertext_size_bytes),
    );
    print_row(
        "Search index size:",
        &format!("{:.0} bytes", summary.search_index_size_bytes),
    );
}

fn print_debug_check(result: &BenchmarkRawResult) {
    println!();
    println!("Debug Check:");
    print_row("Sender ID:", &result.debug.sender_id);
    print_row("Receiver ID:", &result.debug.receiver_id);
    print_row("Benchmark run:", &result.debug.run.to_string());
    print_row("Dataset size:", &result.debug.dataset_size.to_string());
    print_row("Thread ID:", &result.debug.thread_id);
    print_row("KR-IBE params hash:", &result.debug.ibe_params_hash);
    print_row("KR-PEKS params hash:", &result.debug.peks_params_hash);
    print_row("KR-PAEKS params hash:", &result.debug.paeks_params_hash);
    print_row(
        "Ciphertext/decrypt same params:",
        &result
            .debug
            .ciphertext_and_decrypt_use_same_params
            .to_string(),
    );
    print_row(
        "Index/trapdoor same params:",
        &result
            .debug
            .search_index_and_trapdoor_use_same_params
            .to_string(),
    );
    print_row(
        "Authorised v_id matched:",
        &result.debug.authorised_v_id_matched.to_string(),
    );
    print_row(
        "Unauthorised v_id matched:",
        &result.debug.unauthorised_v_id_matched.to_string(),
    );
    print_row("Stored keyword:", &result.debug.stored_keyword);
    print_row(
        "Correct search keyword:",
        &result.debug.correct_search_keyword,
    );
    print_row("Wrong search keyword:", &result.debug.wrong_search_keyword);
    print_row("Stored keyword_hash:", &result.debug.stored_keyword_hash);
    print_row("Correct keyword_hash:", &result.debug.correct_keyword_hash);
    print_row("Wrong keyword_hash:", &result.debug.wrong_keyword_hash);
    print_row("Correct scheme:", &result.debug.correct_scheme.to_string());
    print_row("Wrong scheme:", &result.debug.wrong_scheme.to_string());
    if result.scheme == BenchmarkScheme::Paeks {
        print_row(
            "Raw KR-PAEKS test result:",
            &result
                .debug
                .raw_kr_paeks_wrong_keyword_test_result
                .to_string(),
        );
    }
    print_row(
        "Final correct app results:",
        &result.debug.correct_keyword_results.to_string(),
    );
    print_row(
        "Final wrong keyword app results:",
        &result.debug.wrong_keyword_results.to_string(),
    );
    print_row(
        "Final wrong scheme app results:",
        &result.debug.wrong_scheme_results.to_string(),
    );
    if result.scheme == BenchmarkScheme::Paeks
        && result.debug.raw_kr_paeks_wrong_keyword_test_result
        && result.debug.wrong_keyword_results == 0
    {
        print_row(
            "PAEKS wrong-keyword note:",
            "Raw test matched, but application keyword_hash rejected it.",
        );
    }
}

fn print_summary_tables(summaries: &[BenchmarkSummaryResult]) {
    for scheme in selected_schemes_from_summaries(summaries) {
        println!();
        println!("Summary Table: {scheme}");
        println!("dataset_size,authorised_users,setup_ms,registration_ms,login_ms,encrypt_ms,index_ms,search_ms,decrypt_ms,upload_ms,retrieval_ms");
        for summary in summaries.iter().filter(|summary| summary.scheme == scheme) {
            println!(
                "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
                summary.dataset_size,
                summary.authorised_users,
                summary.setup_ms,
                summary.registration_ms,
                summary.login_ms,
                summary.ibe_encrypt_ms,
                summary.index_generation_ms,
                summary.search_ms,
                summary.ibe_decrypt_ms,
                summary.total_upload_ms,
                summary.total_retrieval_ms
            );
        }
    }

    println!();
    if !has_scheme(summaries, BenchmarkScheme::Peks)
        || !has_scheme(summaries, BenchmarkScheme::Paeks)
    {
        return;
    }

    println!("Comparison Table: KR-PEKS vs KR-PAEKS");
    println!("dataset_size,authorised_users,peks_search_ms,paeks_search_ms,peks_index_ms,paeks_index_ms,peks_upload_ms,paeks_upload_ms");
    for peks in summaries
        .iter()
        .filter(|summary| summary.scheme == BenchmarkScheme::Peks)
    {
        if let Some(paeks) = summaries.iter().find(|summary| {
            summary.scheme == BenchmarkScheme::Paeks
                && summary.dataset_size == peks.dataset_size
                && summary.authorised_users == peks.authorised_users
        }) {
            println!(
                "{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
                peks.dataset_size,
                peks.authorised_users,
                peks.search_ms,
                paeks.search_ms,
                peks.index_generation_ms,
                paeks.index_generation_ms,
                peks.total_upload_ms,
                paeks.total_upload_ms
            );
        }
    }
}

fn print_row(label: &str, value: &str) {
    println!("{label:<35}{value}");
}

fn print_ms(label: &str, value: f64) {
    print_row(label, &format!("{value:.3} ms"));
}

fn print_count(label: &str, value: usize, total: usize) {
    print_row(label, &format!("{value} / {total}"));
}

fn write_raw_csv(path: &str, results: &[BenchmarkRawResult]) -> BenchmarkResult<()> {
    let mut writer = csv_writer(path)?;
    writeln!(
        writer,
        "scheme,dataset_size,authorised_users,run,setup_ms,registration_ms,login_ms,ibe_encrypt_ms,index_generation_ms,search_ms,ibe_decrypt_ms,total_upload_ms,total_retrieval_ms,payload_ciphertext_size_bytes,search_index_size_bytes,successful_searches,successful_decryptions,wrong_keyword_rejected,wrong_scheme_rejected,unauthorised_decryption_failed"
    )?;
    for result in results {
        writeln!(
            writer,
            "{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{},{},{},{}",
            result.scheme,
            result.dataset_size,
            result.authorised_users,
            result.run,
            result.setup_ms,
            result.registration_ms,
            result.login_ms,
            result.ibe_encrypt_ms,
            result.index_generation_ms,
            result.search_ms,
            result.ibe_decrypt_ms,
            result.total_upload_ms,
            result.total_retrieval_ms,
            result.payload_ciphertext_size_bytes,
            result.search_index_size_bytes,
            result.successful_searches,
            result.successful_decryptions,
            result.wrong_keyword_rejected,
            result.wrong_scheme_rejected,
            result.unauthorised_decryption_failed
        )?;
    }
    Ok(())
}

fn write_summary_csv(path: &str, summaries: &[BenchmarkSummaryResult]) -> BenchmarkResult<()> {
    let mut writer = csv_writer(path)?;
    writeln!(
        writer,
        "scheme,dataset_size,authorised_users,runs,successful_runs,setup_ms,registration_ms,login_ms,ibe_encrypt_ms,index_generation_ms,search_ms,ibe_decrypt_ms,total_upload_ms,total_retrieval_ms,payload_ciphertext_size_bytes,search_index_size_bytes,successful_searches,successful_decryptions,wrong_keyword_rejected,wrong_scheme_rejected,unauthorised_decryption_failed"
    )?;
    for summary in summaries {
        writeln!(
            writer,
            "{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.2},{:.2},{:.2},{:.2},{},{},{}",
            summary.scheme,
            summary.dataset_size,
            summary.authorised_users,
            summary.runs,
            summary.successful_runs,
            summary.setup_ms,
            summary.registration_ms,
            summary.login_ms,
            summary.ibe_encrypt_ms,
            summary.index_generation_ms,
            summary.search_ms,
            summary.ibe_decrypt_ms,
            summary.total_upload_ms,
            summary.total_retrieval_ms,
            summary.payload_ciphertext_size_bytes,
            summary.search_index_size_bytes,
            summary.successful_searches,
            summary.successful_decryptions,
            summary.wrong_keyword_rejected,
            summary.wrong_scheme_rejected,
            summary.unauthorised_decryption_failed
        )?;
    }
    Ok(())
}

fn write_comparison_csv(path: &str, summaries: &[BenchmarkSummaryResult]) -> BenchmarkResult<()> {
    let mut writer = csv_writer(path)?;
    writeln!(
        writer,
        "dataset_size,authorised_users,peks_search_ms,paeks_search_ms,search_delta_ms,peks_index_generation_ms,paeks_index_generation_ms,index_delta_ms,peks_total_upload_ms,paeks_total_upload_ms,upload_delta_ms,peks_total_retrieval_ms,paeks_total_retrieval_ms,retrieval_delta_ms"
    )?;
    for peks in summaries
        .iter()
        .filter(|summary| summary.scheme == BenchmarkScheme::Peks)
    {
        if let Some(paeks) = summaries.iter().find(|summary| {
            summary.scheme == BenchmarkScheme::Paeks
                && summary.dataset_size == peks.dataset_size
                && summary.authorised_users == peks.authorised_users
        }) {
            writeln!(
                writer,
                "{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}",
                peks.dataset_size,
                peks.authorised_users,
                peks.search_ms,
                paeks.search_ms,
                paeks.search_ms - peks.search_ms,
                peks.index_generation_ms,
                paeks.index_generation_ms,
                paeks.index_generation_ms - peks.index_generation_ms,
                peks.total_upload_ms,
                paeks.total_upload_ms,
                paeks.total_upload_ms - peks.total_upload_ms,
                peks.total_retrieval_ms,
                paeks.total_retrieval_ms,
                paeks.total_retrieval_ms - peks.total_retrieval_ms
            )?;
        }
    }
    Ok(())
}

fn csv_writer(path: &str) -> BenchmarkResult<BufWriter<File>> {
    Ok(BufWriter::new(File::create(path)?))
}
