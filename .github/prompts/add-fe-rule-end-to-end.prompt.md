---
agent: "agent"
description: "Add a new FE rule end-to-end: implement rule, register it, add tests, and update docs/changelog."
---

# Add FE Rule End-to-End

Add one new FE rule to FE203 and complete all required updates.

Inputs:
- Rule ID (FE###): {{rule_id}}
- Rule name: {{rule_name}}
- Category: {{category}}
- Severity: {{severity}}
- Detection goal: {{goal}}
- Suggestion text: {{suggestion}}

Required implementation steps:
1. Implement rule logic in the correct module under src/rules/.
2. Register the rule in src/rules/mod.rs using stable ordering.
3. Add or update unit tests in the rule module.
4. Update tests/pipeline.rs if the rule changes end-to-end expected findings.
5. Ensure rule metadata is consistent:
   - id
   - name
   - category
   - severity
   - description
   - suggestion (and example, if applicable)

Required documentation updates:
1. Update the matching docs/rules/*.md file.
2. Update docs/cli-reference.md if output or flags changed.
3. Add changelog entry in docs/changelog.md.

Output requirements:
- Summarize changed files.
- Explain detection behavior and known limitations.
- Provide one quick usage example showing expected finding output context.
