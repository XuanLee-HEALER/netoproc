pub mod json;
pub mod pretty;
pub mod tsv;

use std::io::Write;

use crate::cli::OutputFormat;
use crate::error::NetopError;
use crate::model::traffic::StatsState;

/// Write a snapshot of per-process traffic stats in the specified format.
///
/// TSV and JSON output only the per-process data (backward compatible).
/// Pretty output additionally shows Unknown traffic sub-rows by remote address.
pub fn write_snapshot(
    state: &StatsState,
    format: OutputFormat,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    match format {
        OutputFormat::Tsv => tsv::write_tsv(&state.by_process, writer),
        OutputFormat::Json => json::write_json(&state.by_process, writer),
        OutputFormat::Pretty => pretty::write_pretty(state, writer),
    }
}
