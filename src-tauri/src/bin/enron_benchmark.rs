fn main() {
    let config = match k_resilient_suite_react_lib::system::benchmark::BenchmarkConfig::from_args(
        std::env::args().skip(1),
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Benchmark argument error: {error}");
            eprintln!(
                "Usage: cargo run --release --bin enron_benchmark -- [--threads N] [--dataset-sizes CSV] [--authorised-users CSV] [--runs N] [--schemes KR-PEKS,KR-PAEKS] [--output-prefix NAME] [--debug-raw]"
            );
            std::process::exit(2);
        }
    };

    if let Err(error) = k_resilient_suite_react_lib::system::benchmark::run_enron_benchmark(config)
    {
        eprintln!("Benchmark failed: {error}");
        std::process::exit(1);
    }
}
