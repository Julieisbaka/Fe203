use std::process::Command;

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
        if is_cargo_bin_executable_path(&exe) {
            return;
        }
        if path_resolves_current_exe(&exe) {
            return;
        }
        let Some(dir) = exe.parent() else {
            return;
        };
        let dir_str = dir.to_string_lossy().to_string();

        if process_path_contains_dir(&dir_str) {
            return;
        }

        match prioritize_user_path_via_powershell(&dir_str) {
            Some(true) => {
                prioritize_process_path(&dir_str);
                eprintln!(
                    "info: prioritized {} in your user PATH; open a new terminal to use this fe203 globally",
                    dir.display()
                );
            }
            Some(false) => {
                // The persistent user PATH is already correct, but the current terminal
                // session may still be stale.
                prioritize_process_path(&dir_str);
            }
            None => {
                // Best effort: make fe203 available in this process even if persisting
                // the user PATH failed.
                prioritize_process_path(&dir_str);
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

#[cfg(windows)]
fn is_cargo_bin_executable_path(path: &std::path::Path) -> bool {
    let normalized = normalize_path_entry(&path.to_string_lossy());
    if normalized.contains("/.cargo/bin/") || normalized.contains("\\.cargo\\bin\\") {
        return true;
    }

    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let cargo_bin = format!("{}\\bin", cargo_home.trim_end_matches(['\\', '/']));
        if normalized.starts_with(&normalize_path_entry(&cargo_bin)) {
            return true;
        }
    }

    false
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
fn process_path_contains_dir(dir: &str) -> bool {
    let target = normalize_path_entry(dir);
    path_entries().into_iter().any(|entry| entry == target)
}

#[cfg(windows)]
fn path_resolves_current_exe(exe: &std::path::Path) -> bool {
    let Some(file_name) = exe.file_name() else {
        return false;
    };
    let target = canonical_or_normalized(exe);

    path_entries()
        .into_iter()
        .map(std::path::PathBuf::from)
        .map(|dir| dir.join(file_name))
        .find(|candidate| candidate.is_file())
        .map(|candidate| canonical_or_normalized(&candidate) == target)
        .unwrap_or(false)
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

    #[test]
    fn recognizes_auto_path_disable_values() {
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
    fn cargo_bin_executable_path_is_detected() {
        assert!(is_cargo_bin_executable_path(Path::new(
            r"C:\Users\caspe\.cargo\bin\fe203.exe"
        )));
        assert!(!is_cargo_bin_executable_path(Path::new(
            r"C:\repo\target\debug\fe203.exe"
        )));
    }

    #[cfg(windows)]
    #[test]
    fn dir_match_ignores_case_and_trailing_slash() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("PATH", r"C:\Tools\Fe203;C:\Other");
        }
        assert!(process_path_contains_dir(r"c:\tools\fe203\"));
        assert!(!process_path_contains_dir(r"c:\missing"));
    }

    #[cfg(windows)]
    #[test]
    fn prioritize_process_path_moves_dir_to_front() {
        // SAFETY: test-local environment mutation.
        unsafe {
            std::env::set_var("PATH", r"C:\Users\caspe\.cargo\bin;C:\Tools\Fe203;C:\Other");
        }
        prioritize_process_path(r"C:\Tools\Fe203");
        let path = std::env::var("PATH").unwrap();
        assert!(path.starts_with(r"C:\Tools\Fe203;"));
    }
}
