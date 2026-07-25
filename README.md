# AOD Monitoring Tools

eBPF-based monitoring tools for tracing SMB/CIFS and NFS filesystem operations using libbpf CO-RE.

## Prerequisites

- Linux kernel with BTF support
- clang
- libbpf, libelf, zlib (dev packages)
- bpftool

On Ubuntu/Debian:
```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-$(uname -r)
```

## Build

```bash
make            # build all tools
make smbslower  # build a single tool
make clean      # remove build artifacts
```

Binaries are placed in `src/bin/`, intermediate files (including the skel and object files) in `src/.output/`.

## Project Structure

```
src/
├── bpf/         # eBPF kernel-space programs (.bpf.c)
├── user/        # Userspace loaders (.c)
├── include/     # Shared headers (vmlinux.h, cifs_btf.h, diag structs)
└── shm_writer.c # Common shared memory ring buffer for event export
```

## Tools

### Generic Filesystem I/O Monitoring

- **iosnoop** — Trace filesystem I/O syscalls across all filesystems with optional mount point filtering.
  - Traces common filesystem syscalls: open, openat, read, write, close, stat, lstat
  - Captures file paths, process information (PID, UID, GID, comm), and syscall return values
  - Optional filtering by mount point (device-level filtering for efficiency)
  - eBPF-based syscall tracepoint instrumentation (sys_enter/sys_exit)
  - Ring buffer export for event collection and analysis

### SMB/CIFS Monitoring

- **smbslower** — Trace slow SMB/CIFS operations with configurable latency threshold and command filtering.

### NFS Monitoring

- **nfsslower** — Trace slow NFS operations on both NFSv3 and NFSv4 with configurable latency threshold.
  - Detects NFS operations (READ, WRITE, OPEN, CLOSE, etc.) that exceed latency thresholds
  - eBPF-based tracing via `tp_btf` hooks on RPC layer (`rpc_task_begin`, `rpc_task_complete`)
  - Outputs operation type, latency, file path (via CO-RE), and client process info
  - Ring buffer export for integration with userspace anomaly detection

- **nfsiosnoop** — Trace NFS operation results and error codes with per-command analysis.
  - Detects NFS error returns (NFS4ERR_BAD_STATEID, NFS4ERR_OLD_STATEID, etc.)
  - eBPF-based tracing via `tp_btf` hooks on NFS/RPC layers
  - Extracts RPC task details (proc, vers) and error codes from kernel structures
  - Ring buffer export for batch error anomaly detection
  - Supports protocol-specific error filtering and categorization

## Usage

### smbslower

```bash
sudo ./src/bin/smbslower -m 50          # trace ops slower than 50ms
sudo ./src/bin/smbslower -c 8,9         # trace only READ (0x08) and WRITE (0x09)
sudo ./src/bin/smbslower -x 13          # exclude ECHO commands
sudo ./src/bin/smbslower -d 30          # trace for 30 seconds
```

### nfsslower

```bash
sudo ./src/bin/nfsslower -m 50          # trace NFS ops slower than 50ms
sudo ./src/bin/nfsslower -d 30          # trace for 30 seconds
sudo ./src/bin/nfsslower -v 4           # filter to NFSv4 only
```

### nfsiosnoop

```bash
sudo ./src/bin/nfsiosnoop                # trace all NFS operations and errors
sudo ./src/bin/nfsiosnoop -d 30          # trace for 30 seconds and exit
sudo ./src/bin/nfsiosnoop -e BAD_STATEID # filter specific NFS errors (comma-separated)
```

### iosnoop

```bash
sudo ./src/bin/iosnoop                          # trace all filesystem I/O syscalls
sudo ./src/bin/iosnoop -d 30                    # trace for 30 seconds
sudo ./src/bin/iosnoop -m /mnt/nfs-encrypted   # filter events only from specific mount
sudo ./src/bin/iosnoop -v                       # verbose output with BPF debug info
sudo ./src/bin/iosnoop -m /tmp -d 60            # trace /tmp mount for 60 seconds
```

#### Output Format

```
TIME     PID    COMM             TYPE     RET PATH
14:23:45 12345  bash             OPEN       3 /tmp/testfile.txt
14:23:45 12345  bash             READ     512 read
14:23:45 12345  bash             WRITE    512 write
14:23:45 12345  bash             CLOSE      0 close
```

**Columns:**
- **TIME**: Timestamp (HH:MM:SS)
- **PID**: Process ID
- **COMM**: Command name (truncated to 16 chars)
- **TYPE**: Syscall type (OPEN, READ, WRITE, CLOSE, STAT, LSTAT)
- **RET**: Syscall return value (bytes for read/write, fd for open, 0 for success on close)
- **PATH**: File path (for open/stat/lstat) or syscall name (for read/write/close)
