/// Returns (1-based column of the call start, argument text) for each
/// occurrence of `call` in a line.
pub(super) fn call_arguments(line: &str, call: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut start = 0;
    while let Some(pos) = line[start..].find(call) {
        let call_idx = start + pos;
        let args_start = call_idx + call.len();
        let mut depth = 1i32;
        let mut end = None;
        for (offset, ch) in line[args_start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(args_start + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = end {
            found.push((call_idx + 1, line[args_start..end].to_string()));
            start = end + 1;
        } else {
            start = args_start;
        }
    }
    found
}
