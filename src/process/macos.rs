// macOS process table — delegates to system::process (libproc-based).

pub fn build_process_table() -> crate::model::traffic::ProcessTable {
    crate::system::process::build_process_table()
}
