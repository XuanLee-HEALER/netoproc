# Fish completions for netoproc — per-process network traffic monitor
# Install: cp completions/netoproc.fish ~/.config/fish/completions/

complete -c netoproc -f  # no file completion by default

# --duration <SECONDS>  Snapshot mode
complete -c netoproc -l duration -d 'Snapshot mode: collect for N seconds then exit' -r -xa '1 2 3 5 10 15 30'

# --monitor  TUI mode (default)
complete -c netoproc -l monitor -d 'Explicitly enter monitor (TUI) mode'

# --format <FORMAT>  Output format for snapshot mode
complete -c netoproc -l format -d 'Output format for snapshot mode' -r -xa 'tsv json pretty'

# --interface <IFACE>  Specific network interface
complete -c netoproc -l interface -d 'Monitor only the specified network interface' -r -xa '(ifconfig -l | string split " ")'

# --no-dns  Disable DNS observatory
complete -c netoproc -l no-dns -d 'Disable DNS observatory'

# --bpf-buffer <BYTES>  BPF kernel buffer size
complete -c netoproc -l bpf-buffer -d 'BPF kernel buffer size in bytes (default: 2097152)' -r -xa '65536 262144 1048576 2097152 4194304 8388608 16777216'

# --sort <COLUMN>  Initial sort column (monitor mode)
complete -c netoproc -l sort -d 'Initial sort column for monitor mode' -r -xa 'traffic pid name connections'

# --no-color  Disable colored output
complete -c netoproc -l no-color -d 'Disable colored output'

# --filter <PATTERN>  Filter processes by pattern
complete -c netoproc -l filter -d 'Filter by process name pattern' -r

# --help / --version
complete -c netoproc -l help -s h -d 'Print help'
complete -c netoproc -l version -s V -d 'Print version'
