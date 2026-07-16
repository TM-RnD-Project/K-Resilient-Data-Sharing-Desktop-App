# K-Resilient Data Sharing Desktop App

A React/Tauri demonstration application combining KR-IBI authentication, KR-IBE payload encryption, and KR-PEKS/KR-PAEKS encrypted keyword search.

## Build and run

Install a current Node.js LTS release, the Rust stable toolchain, and the [Tauri 2 platform prerequisites](https://v2.tauri.app/start/prerequisites/). On Windows this includes Microsoft C++ Build Tools and WebView2.

```bash
npm install
npm run tauri dev
```

Create an optimized desktop build with:

```bash
npm run tauri build
```

The Rust backend can be checked independently from `src-tauri/`:

```bash
cargo test
cargo build --release
```

## Enron benchmark reproducibility

The benchmark expects the MySQL dump `dataset/EnronMailDB.sql`. The repository copy contains `INSERT INTO` rows whose first fields are date, nullable legacy address fields, sender (`X-From`), receiver (`X-To`), and message body. No database server or CSV conversion is required: `src-tauri/src/system/benchmark.rs` parses the SQL rows directly, unescapes MySQL string escapes, discards incomplete rows, and selects the requested number of valid records in file order.

For each record, the benchmark uses the first alphabetic word from an embedded `Subject:` line when one is present. Otherwise it uses the first body word containing at least four alphabetic characters. The keyword is stripped to alphanumeric characters, lowercased, and rejected if fewer than four characters remain.

Run the complete benchmark from `src-tauri/`:

```bash
cargo clean
cargo build --release --bin enron_benchmark
cargo run --release --bin enron_benchmark -- --threads 16
```

Add raw diagnostic checks with:

```bash
cargo run --release --bin enron_benchmark -- --threads 16 --debug-raw
```

The default matrix uses dataset sizes 100, 500, 1,000, 5,000, and 10,000; authorized-user counts 1, 5, 10, and 20; 100 runs per setting; and both KR-PEKS and KR-PAEKS. Records are constructed programmatically using the same backend cryptographic routines as the desktop application. The selected retrieval record uses AES-GCM record-context binding; non-selected records use placeholder payload ciphertexts because only their searchable indexes are needed for scaling measurements.

Generated measurements are written to:

- `benchmark_results/enron_raw_results.csv`
- `benchmark_results/enron_summary_results.csv`
- `benchmark_results/enron_peks_vs_paeks_comparison.csv`
- `benchmark_results/correctness_results.csv`
- `benchmark_results/run_metadata.txt`

Thread-selection pilot evidence is kept separately in `benchmark_results/thread_scaling_pilot.csv` and `benchmark_results/thread_scaling_pilot_metadata.txt`. The repository also includes the available plotted benchmark outputs under `benchmark_results/figures/`.
