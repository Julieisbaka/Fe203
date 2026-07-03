//! Minimal std-only CLI argument parsing.
// fe203-ignore-file FE020

mod parser;
pub(crate) mod ui;

pub use parser::{parse, CliOptions};
pub use ui::{intro_text, usage_text};
pub(crate) use ui::{terminal_profile, TerminalProfile};
