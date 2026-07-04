pub(crate) struct ParsedFunction<'a> {
    pub(crate) line_no: usize,
    pub(crate) end_line: usize,
    pub(crate) header: &'a str,
    pub(crate) body: &'a str,
}

pub(crate) struct Invocation<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) path: &'a str,
    pub(crate) kind: InvocationKind,
    pub(crate) args: Option<&'a str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvocationKind {
    Call,
    Macro,
}

pub(crate) struct MethodCall<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) name: &'a str,
    pub(crate) args: &'a str,
}

pub(crate) struct MethodChain<'a> {
    pub(crate) line_no: usize,
    pub(crate) column: usize,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) root: &'a str,
    pub(crate) root_args: Option<&'a str>,
    pub(crate) calls: Vec<MethodCall<'a>>,
}
