use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Default benchmark fixture directory used when no path argument is provided.
const DEFAULT_TARGET_DIR: &str = "benchmarks/workload";
/// Default number of measured benchmark iterations.
const DEFAULT_ITERATIONS: usize = 5;

/// Entry point for the local CLI benchmark harness.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target_dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TARGET_DIR));
    let iterations = args
        .get(1)
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ITERATIONS);

    if !target_dir.exists() {
        eprintln!("error: benchmark target does not exist: {}", target_dir.display());
        std::process::exit(2);
    }

    if let Err(err) = ensure_fe203_binary_built() {
        eprintln!("error: {err}");
        std::process::exit(2);
    }

    let fe203_path = fe203_binary_path();
    if !fe203_path.is_file() {
        eprintln!(
            "error: fe203 binary not found after build: {}",
            fe203_path.display()
        );
        std::process::exit(2);
    }

    println!("fe203 benchmark harness");
    println!("target: {}", target_dir.display());
    println!("iterations: {iterations}");
    println!("binary: {}", fe203_path.display());

    // Warm-up run to reduce first-run noise in measured iterations.
    if let Err(err) = run_once(&fe203_path, &target_dir) {
        eprintln!("error: warm-up run failed: {err}");
        std::process::exit(1);
    }

    let mut times = Vec::with_capacity(iterations);
    for idx in 0..iterations {
        let start = Instant::now();
        if let Err(err) = run_once(&fe203_path, &target_dir) {
            eprintln!("error: iteration {} failed: {err}", idx + 1);
            std::process::exit(1);
        }
        let elapsed = start.elapsed();
        times.push(elapsed);
        println!("run {:>2}: {}", idx + 1, format_duration(elapsed));
    }

    let summary = summarize(&times);
    println!("\nsummary");
    println!("min:    {}", format_duration(summary.min));
    println!("max:    {}", format_duration(summary.max));
    println!("mean:   {}", format_duration(summary.mean));
    println!("median: {}", format_duration(summary.median));
}

/// Ensures the `fe203` binary is up to date before running benchmarks.
fn ensure_fe203_binary_built() -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["build", "--quiet", "--bin", "fe203"])
        .status()
        .map_err(|err| format!("failed to run cargo build: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err("cargo build --bin fe203 failed".to_string())
    }
}

/// Resolves the debug `fe203` binary next to this harness executable.
fn fe203_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("target/debug"));
    path.set_file_name(exe_name("fe203"));
    path
}

/// Runs one CLI scan for benchmark measurement.
fn run_once(binary: &Path, target_dir: &Path) -> Result<(), String> {
    let status = Command::new(binary)
        .arg(target_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to run {}: {err}", binary.display()))?;

    if status.success() || status.code() == Some(1) {
        Ok(())
    } else {
        Err(format!("unexpected exit code: {:?}", status.code()))
    }
}

/// Platform-aware executable file name helper.
fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// Summary stats for benchmark run durations.
struct Stats {
    min: Duration,
    max: Duration,
    mean: Duration,
    median: Duration,
}

/// Computes min/max/mean/median from collected iteration durations.
fn summarize(times: &[Duration]) -> Stats {
    let mut sorted = times.to_vec();
    sorted.sort();

    let min = *sorted.first().unwrap_or(&Duration::from_millis(0));
    let max = *sorted.last().unwrap_or(&Duration::from_millis(0));

    let total_secs: f64 = sorted.iter().map(Duration::as_secs_f64).sum();
    let mean_secs = if sorted.is_empty() {
        0.0
    } else {
        total_secs / sorted.len() as f64
    };
    let mean = Duration::from_secs_f64(mean_secs);

    let median = if sorted.is_empty() {
        Duration::from_millis(0)
    } else {
        sorted[sorted.len() / 2]
    };

    Stats {
        min,
        max,
        mean,
        median,
    }
}

/// Formats durations for stable benchmark console output.
fn format_duration(value: Duration) -> String {
    let millis = value.as_secs_f64() * 1000.0;
    format!("{millis:.2}ms")
}
