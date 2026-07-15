use std::path::Path;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(windows)]
pub(super) fn schedule_windows_replace_and_launch(
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
  Copy-Item -Path '{replacement}' -Destination '{current}' -Force;\
  Remove-Item -Path $oldExe -Force -ErrorAction SilentlyContinue;\
  & '{current}' --version;\
  Remove-Item -Path '{temp_dir}' -Recurse -Force -ErrorAction SilentlyContinue;\
}}catch{{\
  $null=Move-Item -LiteralPath $oldExe -Destination '{current}' -Force -ErrorAction SilentlyContinue;\
  throw;\
}};",
        pid = pid,
        replacement = ps_single_quote_escape(&replacement_binary.to_string_lossy()),
        current = ps_single_quote_escape(&current_exe.to_string_lossy()),
        temp_dir = ps_single_quote_escape(&temp_dir.to_string_lossy()),
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
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let staging_name = format!(".fe203-update-{}-{nanos}", std::process::id());
    let replacement_path = current_exe
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?
        .join(staging_name);

    std::fs::copy(replacement_binary, &replacement_path)
        .map_err(|err| format!("failed to stage replacement binary: {err}"))?;

    if let Ok(existing_meta) = std::fs::metadata(current_exe) {
        let mode = existing_meta.permissions().mode();
        let _ = std::fs::set_permissions(&replacement_path, std::fs::Permissions::from_mode(mode));
    }

    std::fs::rename(&replacement_path, current_exe).map_err(|err| {
        let _ = std::fs::remove_file(&replacement_path);
        format!("failed to replace current executable: {err}")
    })
}

#[cfg(unix)]
pub(super) fn launch_updated_binary(exe: &Path) -> Result<i32, String> {
    let status = Command::new(exe)
        .arg("--version")
        .status()
        .map_err(|err| format!("updated binary installed but failed to launch: {err}"))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(windows)]
pub(super) fn ps_single_quote_escape(input: &str) -> String {
    input.replace('\'', "''")
}
