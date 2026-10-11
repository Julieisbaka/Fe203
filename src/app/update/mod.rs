use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

mod json_scan;
mod platform;
mod release;
mod transfer;
mod types;

#[cfg(test)]
mod tests;

#[cfg(unix)]
use platform::replace_binary_in_place_unix;
#[cfg(windows)]
use platform::schedule_windows_replace;
use release::latest_release_info;
use transfer::{download_release_asset, extract_archive, find_file_recursively};
use types::SemverTriplet;

pub(super) fn run_check_update(current_version: &str) -> i32 {
    match latest_release_info() {
        Ok(release) => {
            let Some(current) = parse_semver_triplet(current_version) else {
                eprintln!("error: invalid current version: {current_version}");
                return 2;
            };

            if release.version > current {
                println!(
                    "update available: {} -> {}",
                    current_version, release.version_text
                );
                if release.asset_url.is_empty() {
                    println!(
                        "note: no compatible release asset found for this OS/architecture; install manually from GitHub Releases"
                    );
                } else {
                    println!("run `fe203 --self-update` to install the latest release binary");
                }
            } else {
                println!("fe203 is up to date ({current_version})");
            }
            0
        }
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}

pub(super) fn run_self_update(current_version: &str) -> i32 {
    match perform_self_update(current_version) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}

fn perform_self_update(current_version: &str) -> Result<i32, String> {
    let release = latest_release_info()?;
    let current = parse_semver_triplet(current_version)
        .ok_or_else(|| format!("invalid current version: {current_version}"))?;

    if release.version <= current {
        println!("fe203 is already up to date ({current_version})");
        return Ok(0);
    }
    if release.asset_url.is_empty() {
        return Err(
            "latest release does not provide a compatible asset for this OS/architecture"
                .to_string(),
        );
    }

    let exe = std::env::current_exe()
        .map_err(|err| format!("cannot locate current executable: {err}"))?;
    if is_development_executable_path(&exe) {
        return Err(
            "refusing to self-update a development target binary (target/debug or target/release)"
                .to_string(),
        );
    }

    let tmp = make_temp_update_dir()?;
    let archive_path = tmp.join(release.archive_file_name());
    let prepared_binary = (|| {
        download_release_asset(&release.asset_url, &archive_path)?;
        extract_archive(&archive_path, &tmp, release.archive_kind)?;
        let extracted_binary = find_file_recursively(&tmp, release.binary_name)
            .ok_or_else(|| format!("downloaded archive did not contain {}", release.binary_name))?;
        verify_binary_version(&extracted_binary, &release.version_text)?;
        Ok::<_, String>(extracted_binary)
    })();
    let extracted_binary = match prepared_binary {
        Ok(binary) => binary,
        Err(error) => {
            return Err(cleanup_temp_dir_error(&tmp, error));
        }
    };

    #[cfg(windows)]
    {
        if let Err(error) =
            schedule_windows_replace(&exe, &extracted_binary, &tmp, &release.version_text)
        {
            return Err(cleanup_temp_dir_error(&tmp, error));
        }
        println!(
            "update to {} scheduled; the new binary was verified before replacement.",
            release.version_text
        );
        Ok(0)
    }

    #[cfg(unix)]
    {
        if let Err(error) = replace_binary_in_place_unix(&exe, &extracted_binary) {
            return Err(cleanup_temp_dir_error(&tmp, error));
        }
        std::fs::remove_dir_all(&tmp).map_err(|error| {
            format!("updated binary but failed to remove temporary files: {error}")
        })?;
        println!("updated to {}", release.version_text);
        Ok(0)
    }
}

fn verify_binary_version(binary: &Path, expected_version: &str) -> Result<(), String> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|error| format!("failed to verify downloaded binary: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "downloaded binary version check failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "downloaded binary version output was not valid UTF-8".to_string())?;
    if binary_version_matches(&stdout, expected_version) {
        return Ok(());
    }
    let expected_output = format!("fe203 {expected_version}");
    Err(format!(
        "downloaded binary reported an unexpected version; expected `{expected_output}`, got `{}`",
        stdout.trim()
    ))
}

fn binary_version_matches(stdout: &str, expected_version: &str) -> bool {
    let expected_output = format!("fe203 {expected_version}");
    stdout.lines().any(|line| line.trim() == expected_output)
}

fn cleanup_temp_dir_error(path: &Path, original_error: String) -> String {
    match std::fs::remove_dir_all(path) {
        Ok(()) => original_error,
        Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
            original_error
        }
        Err(cleanup_error) => format!(
            "{original_error}; also failed to clean temporary update files: {cleanup_error}"
        ),
    }
}

fn make_temp_update_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!("fe203-update-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|err| format!("failed to create temp dir: {err}"))?;
    Ok(tmp)
}

fn parse_semver_triplet(version_text: &str) -> Option<SemverTriplet> {
    let trimmed = version_text.trim();
    let without_prefix = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if without_prefix.is_empty() {
        return None;
    }
    let (without_build, build) = match without_prefix.split_once('+') {
        Some((version, build)) if !build.is_empty() && !build.contains('+') => {
            (version, Some(build))
        }
        Some(_) => return None,
        None => (without_prefix, None),
    };
    if build.is_some_and(|metadata| !valid_semver_identifiers(metadata, false)) {
        return None;
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease))
            if !prerelease.is_empty() && valid_semver_identifiers(prerelease, true) =>
        {
            (core, Some(prerelease.to_string()))
        }
        Some(_) => return None,
        None => (without_build, None),
    };

    let mut parts = core.split('.');
    let major = parse_semver_number(parts.next()?)?;
    let minor = parse_semver_number(parts.next()?)?;
    let patch = parse_semver_number(parts.next()?)?;

    if parts.next().is_some() {
        return None;
    }

    Some(SemverTriplet {
        major,
        minor,
        patch,
        prerelease,
    })
}

fn parse_semver_number(input: &str) -> Option<u64> {
    if input.is_empty() || (input.len() > 1 && input.starts_with('0')) {
        return None;
    }
    input.parse().ok()
}

fn valid_semver_identifiers(input: &str, reject_numeric_leading_zero: bool) -> bool {
    input.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !(reject_numeric_leading_zero
                && identifier.bytes().all(|byte| byte.is_ascii_digit())
                && identifier.len() > 1
                && identifier.starts_with('0'))
    })
}

fn parse_github_repo_slug(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('/');
    let suffix = trimmed.strip_prefix("https://github.com/")?;
    let mut parts = suffix.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

fn is_development_executable_path(path: &Path) -> bool {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>();

    parts
        .windows(2)
        .any(|pair| pair[0] == "target" && (pair[1] == "debug" || pair[1] == "release"))
}
