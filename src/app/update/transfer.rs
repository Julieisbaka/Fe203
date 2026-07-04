use std::path::{Path, PathBuf};
use std::process::Command;

use super::types::ArchiveKind;

#[cfg(windows)]
use super::platform::ps_single_quote_escape;

pub(super) fn download_release_asset(url: &str, output_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let script = format!(
            "$ErrorActionPreference='Stop';Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{out}';",
            url = ps_single_quote_escape(url),
            out = ps_single_quote_escape(&output_path.to_string_lossy())
        );

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
            .map_err(|err| format!("failed to download release asset: {err}"))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to download release asset: {}",
            stderr.trim()
        ));
    }

    #[cfg(unix)]
    {
        let out = output_path.to_string_lossy().to_string();
        let curl = Command::new("curl").args(["-fL", "-o", &out, url]).output();

        if let Ok(result) = curl {
            if result.status.success() {
                return Ok(());
            }
        }

        let wget = Command::new("wget").args(["-O", &out, url]).output();
        if let Ok(result) = wget {
            if result.status.success() {
                return Ok(());
            }
        }

        Err("failed to download release asset (tried curl, then wget)".to_string())
    }
}

pub(super) fn extract_archive(
    archive_path: &Path,
    destination_dir: &Path,
    archive_kind: ArchiveKind,
) -> Result<(), String> {
    match archive_kind {
        ArchiveKind::Zip => {
            #[cfg(not(windows))]
            {
                let _ = archive_path;
                let _ = destination_dir;
                Err("zip archive extraction is unsupported on this platform".to_string())
            }

            #[cfg(windows)]
            {
                let script = format!(
                    "$ErrorActionPreference='Stop';Expand-Archive -Path '{zip}' -DestinationPath '{dest}' -Force;",
                    zip = ps_single_quote_escape(&archive_path.to_string_lossy()),
                    dest = ps_single_quote_escape(&destination_dir.to_string_lossy()),
                );

                let output = Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &script,
                    ])
                    .output()
                    .map_err(|err| format!("failed to extract archive: {err}"))?;

                if output.status.success() {
                    return Ok(());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("failed to extract archive: {}", stderr.trim()))
            }
        }
        ArchiveKind::TarGz => {
            #[cfg(not(unix))]
            {
                let _ = archive_path;
                let _ = destination_dir;
                Err("tar.gz extraction is unsupported on this platform".to_string())
            }

            #[cfg(unix)]
            {
                let output = Command::new("tar")
                    .arg("-xzf")
                    .arg(archive_path)
                    .arg("-C")
                    .arg(destination_dir)
                    .output()
                    .map_err(|err| format!("failed to run tar for extraction: {err}"))?;

                if output.status.success() {
                    return Ok(());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("failed to extract archive: {}", stderr.trim()))
            }
        }
    }
}

pub(super) fn find_file_recursively(root: &Path, file_name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            if path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case(file_name))
                .unwrap_or(false)
            {
                return Some(path);
            }
        }
    }

    None
}
