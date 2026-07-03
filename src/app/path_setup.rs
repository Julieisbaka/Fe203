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
        let Some(dir) = exe.parent() else {
            return;
        };
        let dir_str = dir.to_string_lossy().to_string();

        if process_path_contains_dir(&dir_str) {
            return;
        }

        match set_user_path_via_powershell(&dir_str) {
            Some(true) => {
                append_to_process_path(&dir_str);
                eprintln!(
                    "info: added {} to your user PATH; open a new terminal to use fe203 globally",
                    dir.display()
                );
            }
            Some(false) => {
                // The persistent user PATH already has this directory, but the current
                // terminal session may still be stale.
                append_to_process_path(&dir_str);
            }
            None => {
                // Best effort: make fe203 available in this process even if persisting
                // the user PATH failed.
                append_to_process_path(&dir_str);
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
    let target = dir.trim_end_matches(['\\', '/']).to_ascii_lowercase();
    std::env::var("PATH")
        .ok()
        .map(|path| {
            path.split(';').any(|entry| {
                entry
                    .trim()
                    .trim_end_matches(['\\', '/'])
                    .eq_ignore_ascii_case(&target)
            })
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn append_to_process_path(dir: &str) {
    if process_path_contains_dir(dir) {
        return;
    }
    let existing = std::env::var("PATH").unwrap_or_default();
    let new_path = if existing.trim().is_empty() {
        dir.to_string()
    } else {
        format!("{};{}", existing.trim_end_matches(';'), dir)
    };
    // SAFETY: this process intentionally updates its own PATH environment variable.
    unsafe {
        std::env::set_var("PATH", new_path);
    }
}

#[cfg(windows)]
fn set_user_path_via_powershell(dir: &str) -> Option<bool> {
    let escaped = ps_single_quote_escape(dir);
    let script = format!(
        "$d='{escaped}';$p=[Environment]::GetEnvironmentVariable('Path','User');$parts=@();if($p){{$parts=$p -split ';' | ForEach-Object {{$_.Trim().TrimEnd('\\')}} | Where-Object {{$_}}}};$dn=$d.TrimEnd('\\');if($parts -contains $dn){{exit 10}};$n=if([string]::IsNullOrWhiteSpace($p)){{$d}}else{{$p.TrimEnd(';')+';'+$d}};[Environment]::SetEnvironmentVariable('Path',$n,'User');"
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
}
