#[derive(Debug, thiserror::Error)]
pub enum NetopError {
    #[error("{0}")]
    InsufficientPermission(String),
    #[error("cannot open BPF device: {0}")]
    BpfDevice(String),
    #[error("sysctl error: {0}")]
    Sysctl(#[source] std::io::Error),
    #[error("libproc error: {0}")]
    Libproc(String),
    #[error("interface enumeration error: {0}")]
    Interface(#[source] std::io::Error),
    #[error("DNS parse error at offset {offset}: {detail}")]
    DnsParse { offset: usize, detail: String },
    #[error("serialization error: {0}")]
    Serialization(#[source] std::io::Error),
    #[error("capture device error: {0}")]
    CaptureDevice(String),
    #[error("eBPF program error: {0}")]
    EbpfProgram(String),
    #[error("TUI error: {0}")]
    Tui(#[source] std::io::Error),
    #[error("Windows API error: {0}")]
    WinApi(String),
    #[error("fatal: {0}")]
    Fatal(String),
}
