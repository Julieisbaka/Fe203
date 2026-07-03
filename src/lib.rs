//! Fe203 — a fast, modular scanner and linter for Rust code.

mod app;
pub mod cli;
pub mod config;
pub mod finding;
pub mod reporting;
pub mod rules;
pub mod scanner;

pub use app::run;
