#![allow(dead_code)]

pub fn hardcoded_values() -> Vec<&'static str> {
    vec![
        "password = hunter2",
        "api_key = sk_live_1234567890abcdef",
        "token = ghp_1234567890abcdef1234567890abcdef1234",
        "DATABASE_URL=postgres://admin:secret@localhost:5432/app",
        "client_secret = very-secret-value",
        "Authorization: Bearer abc.def.ghi",
    ]
}

pub fn shell_commands() -> Vec<&'static str> {
    vec![
        "sh -c \"echo $USER\"",
        "bash -c \"cat /etc/passwd\"",
        "cmd /c dir",
        "powershell -Command Get-Process",
        "git status",
        "cargo test",
    ]
}

pub fn path_samples() -> Vec<&'static str> {
    vec![
        "../etc/passwd",
        "..\\windows\\system32",
        "assets/images/logo.png",
        "./tmp/build/output",
        "../../secret/keys",
        "safe/path/file.txt",
    ]
}

pub fn evaluate_risk() -> usize {
    let mut risk = 0usize;

    for value in hardcoded_values() {
        if value.contains("password") {
            risk += 10;
        }
        if value.contains("secret") {
            risk += 10;
        }
        if value.contains("token") || value.contains("Bearer") {
            risk += 10;
        }
        if value.contains("postgres://") {
            risk += 8;
        }
    }

    for cmd in shell_commands() {
        if cmd.contains("sh -c") || cmd.contains("bash -c") {
            risk += 8;
        }
        if cmd.contains("cmd /c") || cmd.contains("powershell -Command") {
            risk += 8;
        }
    }

    for path in path_samples() {
        if path.contains("../") || path.contains("..\\") {
            risk += 6;
        }
    }

    risk
}

pub fn render_security_report() -> String {
    let mut out = String::new();
    out.push_str("security-report\n");
    out.push_str(&format!("risk={}\n", evaluate_risk()));

    for value in hardcoded_values() {
        out.push_str("value: ");
        out.push_str(value);
        out.push('\n');
    }
    for cmd in shell_commands() {
        out.push_str("cmd: ");
        out.push_str(cmd);
        out.push('\n');
    }
    for path in path_samples() {
        out.push_str("path: ");
        out.push_str(path);
        out.push('\n');
    }
    out
}
