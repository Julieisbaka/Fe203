use super::*;

#[test]
fn extracts_test_function_with_braces_in_strings_and_comments() {
    let content = "#[test]\nfn sample() {\n    let _ = \"{ not a block }\";\n    /* { nested } */\n    assert_eq!(2, 1 + 1);\n}\n";
    let functions = extract_annotated_functions(content, &["#[test]"]);
    assert_eq!(functions.len(), 1);
    assert!(functions[0].body.contains("assert_eq!"));
}

#[test]
fn collects_macro_and_call_invocations() {
    let invocations = collect_invocations(
        "assert_eq!(2, crate::parse(\"x\")); Command::new(\"fe203\"); env!(\"CARGO_BIN_EXE_fe203\");",
    );
    assert!(invocations
        .iter()
        .any(|call| call.path == "assert_eq" && call.kind == InvocationKind::Macro));
    assert!(invocations
        .iter()
        .any(|call| call.path == "crate::parse" && call.kind == InvocationKind::Call));
    assert!(invocations
        .iter()
        .any(|call| call.path == "Command::new" && call.kind == InvocationKind::Call));
    assert!(invocations
        .iter()
        .any(|call| call.path == "env" && call.kind == InvocationKind::Macro));
}

#[test]
fn collects_multiline_method_chain_with_comments() {
    let chains = collect_method_chains(
        "Command::new(\"sh\")\n    // interpreter flag\n    .arg(\"-c\")\n    .arg(format!(\"echo {}\", user));\n",
    );
    let chain = chains.iter().find(|c| c.root == "Command::new").unwrap();
    assert_eq!(chain.root_args, Some("\"sh\""));
    let names: Vec<&str> = chain.calls.iter().map(|c| c.name).collect();
    assert_eq!(names, ["arg", "arg"]);
    assert_eq!(chain.calls[1].args, "format!(\"echo {}\", user)");
}

#[test]
fn collects_receiver_chain_and_ignores_string_braces() {
    let chains = collect_method_chains("let out = dest.join(entry_name); let s = \"x.join(y)\";\n");
    let chain = chains.iter().find(|c| c.root == "dest").unwrap();
    assert_eq!(chain.calls.len(), 1);
    assert_eq!(chain.calls[0].name, "join");
    assert_eq!(chain.calls[0].args, "entry_name");
    assert_eq!(
        chains
            .iter()
            .filter(|c| c.calls.iter().any(|m| m.name == "join"))
            .count(),
        1
    );
}

#[test]
fn collects_nested_chain_inside_root_call_args() {
    let chains = collect_method_chains("run(base.join(user_input));\n");
    assert!(chains.iter().any(|c| c.root == "run"));
    assert!(chains
        .iter()
        .any(|c| c.root == "base" && c.calls.iter().any(|m| m.name == "join")));
}
