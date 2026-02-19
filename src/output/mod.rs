pub mod json;
pub mod pretty;
pub mod tsv;

use std::collections::HashMap;
use std::io::Write;

use crate::cli::OutputFormat;
use crate::error::NetopError;
use crate::model::traffic::{ProcessKey, TrafficStats};

/// Write a snapshot of per-process traffic stats in the specified format.
pub fn write_snapshot(
    stats: &HashMap<ProcessKey, TrafficStats>,
    format: OutputFormat,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    match format {
        OutputFormat::Tsv => tsv::write_tsv(stats, writer),
        OutputFormat::Json => json::write_json(stats, writer),
        OutputFormat::Pretty => pretty::write_pretty(stats, writer),
    }
}
