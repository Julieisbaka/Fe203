use std::process::{Command, Stdio};

pub(super) fn ensure_exe_dir_in_path() {
    #[cfg(not(windows))]
    {
        return;
    }

    #[cfg(windows)]
    {
        if auto_path_disabled() {
            return;
        }

        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        if !is_fe203_executable(&exe) {
            return;
        }
        if is_development_executable_path(&exe) {
            return;
        }

        let preferred_exe = choose_preferred_fe203_executable(&exe);
        if is_development_executable_path(&preferred_exe) {
            return;
        }

        let Some(dir) = preferred_exe.parent() else {
            return;
        };
        let dir_str = dir.to_string_lossy().to_string();
        let process_needs_update = !process_path_starts_with_dir(&dir_str);

        if process_needs_update {
            prioritize_process_path(&dir_str);
        }

        match prioritize_user_path_via_powershell(&dir_str) {
            Some(true) => {
                eprintln!(
                    "info: prioritized {} in your user PATH; open a new terminal to use this fe203 globally",
                    dir.display()
                );
            }
            Some(false) => {
                // The persistent user PATH is already correct.
            }
            None => {
                // Best effort: current process PATH has already been updated.
                eprintln!(
                    "warning: could not update user PATH automatically; add {} to your PATH manually",
                    dir.display()
                );
            }
        }
    }
}

fn is_fe203_executable(path: &std::path::Path) -> bool {
    path.file_stem()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case("fe203"))
        .unwrap_or(false)
}

fn is_development_executable_path(path: &std::path::Path) -> bool {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>();

    parts
        .windows(2)
        .any(|pair| pair[0] == "target" && (pair[1] == "debug" || pair[1] == "release"))
}

fn auto_path_disabled() -> bool {
    std::env::var("FE203_NO_AUTO_PATH")
        .map(|v| {
            let lower = v.trim().to_ascii_lowercase();
            lower == "1" || lower == "true" || lower == "yes"
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn process_path_starts_with_dir(dir: &str) -> bool {
    let target = normalize_path_entry(dir);
    path_entries()
        .first()
        .map(|entry| entry == &target)
        .unwrap_or(false)
}

#[cfg(windows)]
fn choose_preferred_fe203_executable(current_exe: &std::path::Path) -> std::path::PathBuf {
    let Some(file_name) = current_exe.file_name() else {
        return current_exe.to_path_buf();
    };

    let mut candidates = Vec::new();
    candidates.push(current_exe.to_path_buf());

    for entry in path_entries() {
        let candidate = std::path::PathBuf::from(entry).join(file_name);
        if candidate.is_file() {
            candidates.push(candidate);
        }
    }

    let mut seen = std::collections::HashSet::new();
    candidates.retain(|candidate| seen.insert(canonical_or_normalized(candidate)));

    let mut best = current_exe.to_path_buf();
    let mut best_version = query_fe203_version(current_exe);

    for candidate in candidates {
        let candidate_version = query_fe203_version(&candidate);
        if is_newer_version(candidate_version, best_version) {
            best = candidate;
            best_version = candidate_version;
        }
    }

    best
}

#[cfg(windows)]
fn query_fe203_version(exe: &std::path::Path) -> Option<Fe203Version> {
    let output = Command::new(exe)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    parse_fe203_version_output(&stdout)
}

#[cfg(windows)]
fn is_newer_version(
    candidate: Option<Fe203Version>,
    best: Option<Fe203Version>,
) -> bool {
    match (candidate, best) {
        (Some(candidate), Some(best)) => candidate > best,
        (Some(_), None) => true,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Fe203Version {
    major: u64,
    minor: u64,
    patch: u64,
}

fn parse_fe203_version_output(output: &str) -> Option<Fe203Version> {
    let version_text = output.split_whitespace().nth(1)?;
    parse_semver_triplet(version_text)
}

fn parse_semver_triplet(version_text: &str) -> Option<Fe203Version> {
    let core = version_text
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()?;

    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;

    if parts.next().is_some() {
        return None;
    }

    Some(Fe203Version {
        major,
        minor,
        patch,
    })
}

#[cfg(windows)]
fn prioritize_process_path(dir: &str) {
    let target = normalize_path_entry(dir);
    let mut parts = path_entries()
        .into_iter()
        .filter(|entry| entry != &target)
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();
    parts.insert(0, std::path::PathBuf::from(dir));
    let new_path = std::env::join_paths(parts).unwrap_or_else(|_| dir.into());
    // SAFETY: this process intentionally updates its own PATH environment variable.
    unsafe {
        std::env::set_var("PATH", new_path);
    }
}

#[cfg(windows)]
fn prioritize_user_path_via_powershell(dir: &str) -> Option<bool> {
    let escaped = ps_single_quote_escape(dir);
    let script = format!(
        "$d='{escaped}';$dn=$d.Trim().TrimEnd('\\');$p=[Environment]::GetEnvironmentVariable('Path','User');$parts=@();if($p){{$parts=$p -split ';' | ForEach-Object {{$_.Trim().TrimEnd('\\')}} | Where-Object {{$_}}}};if($parts.Count -gt 0 -and $parts[0].ToLowerInvariant() -eq $dn.ToLowerInvariant()){{exit 10}};$parts=@($dn)+($parts | Where-Object {{$_.ToLowerInvariant() -ne $dn.ToLowerInvariant()}});$n=($parts -join ';');[Environment]::SetEnvironmentVariable('Path',$n,'User');"
    );

    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .ok()?;

    let code = status.code().unwrap_or(1);
    if code == 0 {
        Some(true)
    } else if code == 10 {
        Some(false)
    } else {
        None
    }
}

#[cfg(windows)]
fn path_entries() -> Vec<String> {
    let Some(raw) = std::env::var_os("PATH") else {
        return Vec::new();
    };

    let parsed = std::env::split_paths(&raw)
        .map(|entry| normalize_path_entry(&entry.to_string_lossy()))
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();

    if !parsed.is_empty() {
        return parsed;
    }

    raw.to_string_lossy()
        .split(';')
        .map(normalize_path_entry)
        .filter(|entry| !entry.is_empty())
        .collect()
}

#[cfg(windows)]
fn canonical_or_normalized(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .map(|resolved| normalize_path_entry(&resolved.to_string_lossy()))
        .unwrap_or_else(|_| normalize_path_entry(&path.to_string_lossy()))
}

#[cfg(windows)]
fn normalize_path_entry(input: &str) -> String {
    input
        .trim()
        .trim_matches('"')
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase()
}

#[cfg(windows)]
fn ps_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn recognizes_auto_path_disable_values() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("FE203_NO_AUTO_PATH", "1");
        }
        assert!(auto_path_disabled());
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("FE203_NO_AUTO_PATH", "true");
        }
        assert!(auto_path_disabled());
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::remove_var("FE203_NO_AUTO_PATH");
        }
        assert!(!auto_path_disabled());
    }

    #[test]
    fn executable_name_check_matches_only_fe203() {
        assert!(is_fe203_executable(Path::new(r"C:\tools\fe203.exe")));
        assert!(is_fe203_executable(Path::new("/tmp/fe203")));
        assert!(!is_fe203_executable(Path::new(r"C:\tools\pipeline.exe")));
    }

    #[test]
    fn development_executable_path_is_detected() {
        assert!(is_development_executable_path(Path::new(
            r"C:\repo\target\debug\fe203.exe"
        )));
        assert!(is_development_executable_path(Path::new(
            r"C:\repo\target\release\fe203.exe"
        )));
        assert!(!is_development_executable_path(Path::new(
            r"C:\Users\caspe\.cargo\bin\fe203.exe"
        )));
    }

    #[test]
    fn parses_semver_triplets_from_version_output() {
        assert_eq!(
            parse_fe203_version_output("fe203 0.2.0\n"),
            Some(Fe203Version {
                major: 0,
                minor: 2,
                patch: 0,
            })
        );
        assert_eq!(
            parse_fe203_version_output("fe203 v1.10.3-beta.1+build\n"),
            Some(Fe203Version {
                major: 1,
                minor: 10,
                patch: 3,
            })
        );
        assert_eq!(parse_fe203_version_output("something else"), None);
    }

    #[cfg(windows)]
    #[test]
    fn path_front_match_ignores_case_and_trailing_slash() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("PATH", r"C:\Tools\Fe203;C:\Other");
        }
        let entries = path_entries();
        assert_eq!(entries.first().map(|entry| entry.as_str()), Some(r"c:\tools\fe203"));
        assert!(process_path_starts_with_dir(r"c:\tools\fe203"));
        assert!(!process_path_starts_with_dir(r"c:\other"));
    }

    #[cfg(windows)]
    #[test]
    fn prioritize_process_path_moves_dir_to_front() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("PATH", r"C:\Users\caspe\.cargo\bin;C:\Tools\Fe203;C:\Other");
        }
        prioritize_process_path(r"C:\Tools\Fe203");
        let path = std::env::var("PATH").unwrap();
        assert!(path.starts_with(r"C:\Tools\Fe203;"));
    }
}
