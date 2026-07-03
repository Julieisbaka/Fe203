//! Minimal std-only CLI argument parsing.
// fe203-ignore-file FE020

mod parser;
mod ui;

pub use parser::{parse, CliOptions};
pub use ui::{intro_text, usage_text};
