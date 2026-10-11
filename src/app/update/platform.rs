use std::path::Path;
#[cfg(windows)]
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
pub(super) fn schedule_windows_replace(
    current_exe: &Path,
    replacement_binary: &Path,
    temp_dir: &Path,
    version_text: &str,
) -> Result<(), String> {
    let pid = std::process::id();
    // Wait for the current process to exit, then retry renaming the old binary
    // with exponential backoff to handle brief post-exit file locks (e.g., from
    // antivirus scanners). Rename the old binary out of the way before copying so
    // a locked destination does not prevent the new binary from landing at the
    // original path.
    let script = format!(
        "$ErrorActionPreference='Stop';\
$pidToWait={pid};\
while(Get-Process -Id $pidToWait -ErrorAction SilentlyContinue){{Start-Sleep -Milliseconds 200}};\
$oldExe='{current}'+'.old';\
$null=Remove-Item -Path $oldExe -Force -ErrorAction SilentlyContinue;\
$retries=10;\
$delay=200;\
for($i=0;$i -lt $retries;$i++){{\
  try{{\
    Move-Item -LiteralPath '{current}' -Destination $oldExe -Force;\
    break;\
  }}catch{{\
    if($i -ge $retries-1){{Write-Error \"fe203 self-update: failed to rename current binary after $retries attempts: $_\";throw}}\
    Start-Sleep -Milliseconds $delay;\
    $delay=[Math]::Min($delay*2,2000);\
  }}\
}};\
    try{{\
  Copy-Item -LiteralPath '{replacement}' -Destination '{current}' -Force;\
      $versionOutput=(& '{current}' --version 2>&1 | Out-String).Trim();\
      if($LASTEXITCODE -ne 0 -or $versionOutput -ne '{expected_version}'){{throw \"updated binary verification failed: $versionOutput\"}};\
      Remove-Item -Path $oldExe -Force -ErrorAction SilentlyContinue;\
      Remove-Item -Path '{temp_dir}' -Recurse -Force -ErrorAction SilentlyContinue;\
    }}catch{{\
      Remove-Item -LiteralPath '{current}' -Force -ErrorAction SilentlyContinue;\
      if(Test-Path -LiteralPath $oldExe){{Move-Item -LiteralPath $oldExe -Destination '{current}' -Force}};\
      Remove-Item -Path '{temp_dir}' -Recurse -Force -ErrorAction SilentlyContinue;\
      throw;\
    }};",
            pid = pid,
            replacement = ps_single_quote_escape(&replacement_binary.to_string_lossy()),
            current = ps_single_quote_escape(&current_exe.to_string_lossy()),
            temp_dir = ps_single_quote_escape(&temp_dir.to_string_lossy()),
            expected_version = ps_single_quote_escape(&format!("fe203 {version_text}")),
    );

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .spawn()
        .map_err(|err| format!("failed to launch updater process: {err}"))?;

    println!("scheduled update to {version_text}");
    Ok(())
}

#[cfg(unix)]
pub(super) fn replace_binary_in_place_unix(
    current_exe: &Path,
    replacement_binary: &Path,
) -> Result<(), String> {
    // Use a unique staging filename so a stale leftover from a previous failed
    // update (potentially owned by a different user) does not block this attempt.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("system clock error while staging update: {err}"))?
        .as_nanos();
    let staging_name = format!(".fe203-update-{}-{nanos}", std::process::id());
    let replacement_path = current_exe
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?
        .join(staging_name);

    if let Err(err) = std::fs::copy(replacement_binary, &replacement_path) {
        return Err(cleanup_staging_file(
            &replacement_path,
            format!("failed to stage replacement binary: {err}"),
        ));
    }

    let existing_meta = match std::fs::metadata(current_exe) {
        Ok(metadata) => metadata,
        Err(err) => {
            return Err(cleanup_staging_file(
                &replacement_path,
                format!("failed to inspect current executable permissions: {err}"),
            ));
        }
    };
    let mode = existing_meta.permissions().mode();
    if let Err(err) =
        std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(mode))
    {
        return Err(cleanup_staging_file(
            &replacement_path,
            format!("failed to preserve executable permissions: {err}"),
        ));
    }

    std::fs::rename(&replacement_path, current_exe).map_err(|err| {
        cleanup_staging_file(
            &replacement_path,
            format!("failed to replace current executable: {err}"),
        )
    })
}

#[cfg(unix)]
fn cleanup_staging_file(path: &Path, original_error: String) -> String {
    match std::fs::remove_file(path) {
        Ok(()) => original_error,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => original_error,
        Err(error) => format!("{original_error}; failed to remove staging file: {error}"),
    }
}

#[cfg(windows)]
pub(super) fn ps_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}
