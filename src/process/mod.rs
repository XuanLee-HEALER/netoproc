// Platform-abstracted process table construction.
//
// On macOS: delegates to system::process (libproc-based).
// On Linux: reads /proc/net/tcp[6], /proc/net/udp[6], /proc/<pid>/fd/.
//
// Both platforms export:
//   - build_process_table() -> ProcessTable

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use linux::build_process_table;

#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub use windows::build_process_table;
