# netoproc is a per-process network traffic monitor for macOS.
# See: https://github.com/XuanLee-HEALER/netoproc

complete -c netoproc -l duration -d 'Snapshot mode: collect for N seconds' -xa '1 2 3 5 10 15 30'
complete -c netoproc -l monitor -d 'Enter monitor (TUI) mode'
complete -c netoproc -l format -d 'Output format (snapshot mode)' -xa 'tsv json pretty'
complete -c netoproc -l interface -d 'Monitor specific network interface' -xa '(ifconfig -l | string split " ")'
complete -c netoproc -l no-dns -d 'Disable DNS observatory'
complete -c netoproc -l bpf-buffer -d 'BPF buffer size in bytes' -xa '65536 262144 1048576 2097152 4194304 8388608 16777216'
complete -c netoproc -l sort -d 'Initial sort column' -xa 'traffic pid name connections'
complete -c netoproc -l no-color -d 'Disable colored output'
complete -c netoproc -l filter -d 'Filter by process name' -x
complete -c netoproc -l help -s h -d 'Print help'
complete -c netoproc -l version -s V -d 'Print version'
