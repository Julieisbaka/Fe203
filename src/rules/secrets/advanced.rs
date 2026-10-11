use super::*;
use crate::rules::syntax::collect_method_chains;

pub(super) fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(WeakRandomRule),
        Box::new(SensitiveSerdeDefaultRule),
        Box::new(PermissiveCorsRule),
    ]
}

struct WeakRandomRule;

impl Rule for WeakRandomRule {
    fn id(&self) -> &'static str {
        "FE048"
    }

    fn name(&self) -> &'static str {
        "weak-rng-for-secret"
    }

    fn description(&self) -> &'static str {
        "a non-cryptographic random generator appears to produce a security-sensitive value"
    }

    fn category(&self) -> Category {
        Category::Secrets
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Use an operating-system-backed cryptographic RNG for secrets, keys, and tokens.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["SmallRng", "XorShiftRng", "fastrand", "oorandom"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        const GENERATORS: &[&str] = &["SmallRng", "XorShiftRng", "fastrand", "oorandom"];
        const SECRET_CONTEXT: &[&str] = &[
            "token",
            "secret",
            "password",
            "private_key",
            "session",
            "csrf",
            "nonce",
        ];
        let lines: Vec<_> = ctx.lines().collect();
        lines
            .iter()
            .filter_map(|(line_no, line)| {
                let generator = GENERATORS
                    .iter()
                    .find(|generator| line.contains(**generator))?;
                if is_comment_line(line)
                    || is_rule_ignored(ctx, *line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let index = line_no.saturating_sub(1);
                let start = index.saturating_sub(2);
                let end = (index + 2).min(lines.len().saturating_sub(1));
                let context = lines
                    .iter()
                    .take(end + 1)
                    .skip(start)
                    .map(|(_, text)| text.to_ascii_lowercase())
                    .collect::<Vec<_>>()
                    .join(" ");
                if !SECRET_CONTEXT.iter().any(|word| context.contains(word)) {
                    return None;
                }
                Some(self.finding(
                    ctx,
                    *line_no,
                    line.find(generator).unwrap_or(0) + 1,
                    format!(
                        "non-cryptographic RNG `{generator}` used near a security-sensitive value"
                    ),
                    line,
                ))
            })
            .collect()
    }
}

struct SensitiveSerdeDefaultRule;

impl Rule for SensitiveSerdeDefaultRule {
    fn id(&self) -> &'static str {
        "FE049"
    }

    fn name(&self) -> &'static str {
        "security-sensitive-serde-default"
    }

    fn description(&self) -> &'static str {
        "a custom serde default on an authorization field can grant unintended privileges"
    }

    fn category(&self) -> Category {
        Category::Secrets
    }

    fn severity(&self) -> Severity {
        Severity::Warning
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Make authorization defaults explicit and fail closed when fields are missing.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["serde(default", "is_admin", "permissions", "privilege"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        const SENSITIVE_FIELDS: &[&str] = &[
            "is_admin",
            "admin",
            "permissions",
            "privileges",
            "role",
            "access_level",
        ];
        let lines: Vec<_> = ctx.lines().collect();
        lines
            .iter()
            .enumerate()
            .filter_map(|(index, (line_no, line))| {
                if !line.contains("#[serde(default")
                    || !line.contains('=')
                    || is_comment_line(line)
                    || is_rule_ignored(ctx, *line_no, self.id(), self.name(), self.category())
                {
                    return None;
                }
                let next = lines.get(index + 1).map(|(_, line)| *line).unwrap_or("");
                let field = SENSITIVE_FIELDS
                    .iter()
                    .find(|field| next.contains(**field))?;
                Some(self.finding(
                    ctx,
                    *line_no,
                    line.find("serde").unwrap_or(0) + 1,
                    format!("custom serde default is applied to authorization field `{field}`"),
                    line,
                ))
            })
            .collect()
    }
}

struct PermissiveCorsRule;

impl Rule for PermissiveCorsRule {
    fn id(&self) -> &'static str {
        "FE050"
    }

    fn name(&self) -> &'static str {
        "permissive-cors"
    }

    fn description(&self) -> &'static str {
        "permissive CORS settings may allow untrusted websites to access an API"
    }

    fn category(&self) -> Category {
        Category::Secrets
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn suggestion(&self) -> Option<&'static str> {
        Some("Allow only the trusted origins required by the application.")
    }

    fn prefilter_signatures(&self) -> &'static [&'static str] {
        &["permissive()", "allow_origin", "Any"]
    }

    fn scan(&self, ctx: &FileContext) -> Vec<Finding> {
        let lines: Vec<_> = ctx.lines().collect();
        collect_method_chains(ctx.content)
            .into_iter()
            .flat_map(|chain| {
                chain.calls.into_iter().filter_map(|call| {
                    let permissive = call.name == "permissive"
                        && chain.root.to_ascii_lowercase().contains("cors");
                    let wildcard = call.name == "allow_origin"
                        && (call.args.trim() == "\"*\""
                            || call.args.trim().ends_with("::Any")
                            || call.args.trim() == "Any");
                    if (!permissive && !wildcard)
                        || is_rule_ignored(
                            ctx,
                            call.line_no,
                            self.id(),
                            self.name(),
                            self.category(),
                        )
                    {
                        return None;
                    }
                    let line = lines
                        .iter()
                        .find(|(line_no, _)| *line_no == call.line_no)
                        .map(|(_, line)| *line)?;
                    Some(self.finding(
                        ctx,
                        call.line_no,
                        call.column,
                        "CORS policy allows arbitrary origins".to_string(),
                        line,
                    ))
                })
            })
            .collect()
    }
}
