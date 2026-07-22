A. Impact analysis

The deterministic keyword tag appeared in active Rust backend and benchmark code as `keyword_hash`, computed as `SHA256(trim(keyword).to_lowercase())`.

Affected files and purposes:

| File | Purpose of occurrence | Affected areas |
|---|---|---|
| `src-tauri/src/system/utils.rs` | `keyword_hash()` helper and `record_aad(..., keyword_hash, ...)` | upload, search, AES-GCM AAD, record integrity |
| `src-tauri/src/system/state.rs` | `StoredData.keyword_hash` | stored record shape/size, in-memory serialization shape |
| `src-tauri/src/system/upload.rs` | computed/stored deterministic hash and included it in AAD | upload, decryption compatibility, AAD |
| `src-tauri/src/system/search.rs` | computed query hash and skipped records before KR-PEKS/KR-PAEKS Test | search timing, candidate filtering, leakage |
| `src-tauri/src/system/download.rs` | reconstructed AAD using stored hash | retrieval/download, decryption, AAD |
| `src-tauri/src/system/benchmark.rs` | stored benchmark hash, hash prefilter, debug hash output, AAD input | benchmark search, upload/index timing, retrieval timing, result validity |
| `src-tauri/src/kr_ibe/main.rs` | record-binding test included tag in test AAD | automated tests |

Existing stored records are incompatible with the updated in-memory record shape and AAD. This application stores records in memory, so restart clears them; any future persistent format would need migration.

B. Files modified

- `src-tauri/src/system/utils.rs`: removed `keyword_hash`; removed keyword hash from `record_aad`.
- `src-tauri/src/system/state.rs`: removed `StoredData.keyword_hash`.
- `src-tauri/src/system/upload.rs`: removed hash computation/storage; AAD now uses sender, receiver, mode, search index.
- `src-tauri/src/system/search.rs`: removed query hash and prefilter; search now tests all eligible records.
- `src-tauri/src/system/download.rs`: recomputes AAD without keyword hash.
- `src-tauri/src/system/benchmark.rs`: removed benchmark hash field/prefilter/debug output; benchmark search now tests all eligible records.
- `src-tauri/src/kr_ibe/main.rs`: updated AAD/tamper tests.
- `src-tauri/benchmark_results/*`: updated benchmark outputs, figures, comparison/stat files, patch, and this report.

C. Functional changes

Final search workflow:

`keyword -> KR-PEKS/KR-PAEKS trapdoor -> iterate eligible records -> cryptographic Test -> return matches`.

Eligibility remains session/authentication, owner/receiver, mode, and valid sender key material for PAEKS. No deterministic tag is computed, stored, compared, displayed, or used as a candidate filter in active code.

D. AES-GCM record-binding changes

AAD changed from:

`H_rec(sender || receiver || mode || keyword_hash || enc(search_index))`

to:

`H_rec(sender || receiver || mode || enc(search_index))`

The same AAD construction is used on upload and download/decryption. Tests verify sender, receiver, mode, search-index, ciphertext swap, payload ciphertext tampering, and unauthorized receiver failures.

E. Build and test validation

Commands run:

```powershell
cd src-tauri
cargo fmt
cargo test
cargo build --release
```

Results:

- `cargo fmt`: passed.
- `cargo test`: passed; 2 tests in lib and 2 tests in main passed.
- `cargo build --release`: passed.
- Warnings remain pre-existing/orthogonal: unused imports/variables, deprecated `base64::{encode, decode}`, non-snake-case names, dead code.

Important functional finding:

After removing the tag filter, KR-PAEKS wrong-keyword searches are accepted by the current KR-PAEKS `Test` implementation. The implementation now faithfully exposes the cryptographic Test result instead of hiding it behind the deterministic tag.

F. Benchmark impact assessment

| Metric | Affected? | Technical reason | Needs rerun? | Evidence |
|---|---:|---|---:|---|
| setup | No | no tag code in setup | No | setup functions unchanged |
| registration/key generation | No | no tag code | No | registration code unchanged |
| authentication/login | No | no tag code | No | auth code unchanged |
| index generation | Yes | benchmark timed `build_stored_records`, which previously computed `keyword_hash` | Yes | `build_stored_records` hash removed |
| upload | Yes | total upload includes index generation and AAD construction | Yes | upload AAD changed |
| search | Yes | tag prefilter removed; all eligible records tested | Yes | `search.rs` and `app_search` filter removed |
| retrieval | Yes | total retrieval includes search and decrypt | Yes | benchmark total retrieval changed |
| download/decryption | Yes for validation | AAD reconstruction changed | Yes | `download.rs` AAD changed |
| verification | Yes | wrong-keyword checks now reflect pure Test behavior | Yes | PAEKS wrong keyword now fails benchmark validity |
| index size | No | searchable ciphertext unchanged | Rerun with suite | size unchanged in output |
| stored-record size | Yes | stored hash field removed | Yes conceptually | `StoredData.keyword_hash` removed; no CSV metric exists |
| payload ciphertext size | No | AES-GCM plaintext/ciphertext unchanged | Rerun with suite | output unchanged |
| session-key encapsulation size | No | KR-IBE encapsulation unchanged | No | KR-IBE structure unchanged |

Because the benchmark runner executes the integrated workflow and writes CSVs at the end, the full suite was rerun.

G. New benchmark results

Command used:

```powershell
cd src-tauri
.\target\release\enron_benchmark.exe --threads 8
python benchmark_results\generate_benchmark_figures.py
```

Configuration preserved:

- Dataset: `../dataset/EnronMailDB.sql`
- Dataset sizes: 100, 500, 1000, 5000, 10000
- Authorised identities: 1, 5, 10, 20
- Runs per setting: 100
- Schemes: KR-PEKS and KR-PAEKS
- Workers: 8

Updated files:

- `benchmark_results/enron_raw_results.csv`
- `benchmark_results/enron_summary_results.csv`
- `benchmark_results/enron_peks_vs_paeks_comparison.csv`
- `benchmark_results/figures/*.png`
- `benchmark_results/figures/*.pdf`
- `benchmark_results/tag_removal_metric_stats.csv`
- `benchmark_results/tag_removal_before_after_search_comparison.csv`

H. Before-versus-after comparison

Averages across authorised-user counts:

| Scheme | Dataset | Search before ms | Search after ms | Successful searches before | Successful searches after | Wrong keyword rejected before | Wrong keyword rejected after |
|---|---:|---:|---:|---:|---:|---:|---:|
| KR-PEKS | 100 | 0.947 | 14.888 | 1.42 | 1.42 | 400/400 | 400/400 |
| KR-PEKS | 500 | 1.580 | 75.057 | 3.57 | 3.57 | 400/400 | 400/400 |
| KR-PEKS | 1000 | 2.665 | 151.297 | 6.44 | 6.44 | 400/400 | 400/400 |
| KR-PEKS | 5000 | 6.358 | 749.854 | 17.49 | 17.49 | 400/400 | 400/400 |
| KR-PEKS | 10000 | 6.448 | 1502.754 | 17.49 | 17.49 | 400/400 | 400/400 |
| KR-PAEKS | 100 | 11.332 | 440.070 | 1.42 | 100.00 | 400/400 | 0/400 |
| KR-PAEKS | 500 | 29.555 | 2220.856 | 3.57 | 500.00 | 400/400 | 0/400 |
| KR-PAEKS | 1000 | 53.647 | 4431.592 | 6.44 | 1000.00 | 400/400 | 0/400 |
| KR-PAEKS | 5000 | 143.069 | 22257.053 | 17.49 | 5000.00 | 400/400 | 0/400 |
| KR-PAEKS | 10000 | 145.803 | 44462.421 | 17.49 | 10000.00 | 400/400 | 0/400 |

Raw after-run search statistics are in `tag_removal_metric_stats.csv`.

I. Security impact

The additional equality/frequency/dictionary leakage introduced specifically by the deterministic stored keyword tag has been removed:

- no deterministic keyword tag is stored;
- no query tag is computed;
- no tag comparison is performed;
- no tag-based candidate filtering remains.

This does not claim that all searchable-encryption leakage or all keyword-guessing risk is eliminated.

J. Compatibility and limitations

- In-memory records created by the previous code are incompatible because the stored field and AAD changed.
- KR-PAEKS wrong-keyword rejection no longer passes after tag removal. The current KR-PAEKS Test path accepts all eligible PAEKS records, so `successful_runs` for PAEKS benchmark settings is 0/100 because wrong-keyword rejection is part of the benchmark success predicate.
- Native `git` was unavailable in PATH; the patch artifact was generated from `.git` objects directly.
- Existing warnings remain, but no new build/test failure remains.

K. Deliverables

- Modified source tree in workspace.
- Patch: `benchmark_results/tag_removal_source_changes.patch`
- Raw benchmark output: `benchmark_results/tag_removal_benchmark_stdout_direct.txt`
- Updated raw CSV: `benchmark_results/enron_raw_results.csv`
- Updated summary CSV: `benchmark_results/enron_summary_results.csv`
- Updated comparison CSV: `benchmark_results/enron_peks_vs_paeks_comparison.csv`
- Before snapshots: `benchmark_results/before_tag_removal_*.csv`
- Stats CSV: `benchmark_results/tag_removal_metric_stats.csv`
- Before/after CSV: `benchmark_results/tag_removal_before_after_search_comparison.csv`
- Updated figures: `benchmark_results/figures/*`
