pub mod json;
pub mod pretty;
pub mod tsv;

use std::io::Write;

use crate::cli::OutputFormat;
use crate::error::NetopError;
use crate::model::SystemNetworkState;

/// Write a snapshot of the system network state in the specified format.
pub fn write_snapshot(
    state: &SystemNetworkState,
    format: OutputFormat,
    writer: &mut impl Write,
) -> Result<(), NetopError> {
    match format {
        OutputFormat::Tsv => tsv::write_tsv(state, writer),
        OutputFormat::Json => json::write_json(state, writer),
        OutputFormat::Pretty => pretty::write_pretty(state, writer),
    }
}
