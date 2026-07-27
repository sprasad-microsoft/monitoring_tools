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
  - Traces comprehensive filesystem syscalls:
    - **File operations**: open, openat, read, write, close
    - **File metadata**: stat, lstat, fstat, chmod, fchmod, chown, fchown, truncate, ftruncate
    - **Directory operations**: mkdir, mkdirat, rmdir
    - **File deletion**: unlink, unlinkat
    - **File renaming**: rename, renameat, renameat2
    - **Link operations**: link, linkat, symlink, symlinkat, readlink, readlinkat
    - **Filesystem operations**: mount, umount2
  - Captures file paths, process information (PID, UID, GID, comm), and syscall return values
  - Optional filtering by mount point (device-level filtering for efficiency)
  - eBPF-based syscall tracepoint instrumentation (sys_enter/sys_exit)
  - Ring buffer export for event collection and analysis

- **ioslower** — Trace slow filesystem I/O syscalls with configurable latency threshold.
  - Measures latency of filesystem syscalls (same comprehensive syscall list as iosnoop)
  - Configurable latency threshold (default: 10ms)
  - Timestamps for entry/exit with microsecond precision
  - Captures file paths, process info, and syscall return values
  - Efficient filtering: only exports events exceeding latency threshold
  - Useful for identifying performance bottlenecks in filesystem operations
  - eBPF-based latency measurement via syscall tracepoints
  - Ring buffer export for latency-based analysis

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
TIME     PID    COMM             TYPE       RET PATH
14:23:45 12345  bash             OPEN         3 /tmp/testfile.txt
14:23:45 12345  bash             READ       512 read
14:23:45 12345  bash             WRITE      512 write
14:23:45 12345  bash             MKDIR        0 mode=0755           /tmp/newdir
14:23:45 12345  bash             UNLINK       0 -                   /tmp/oldfile.txt
14:23:45 12345  bash             MOUNT        0 flags=0x0           /mnt/share
14:23:45 12345  bash             CHMOD        0 mode=0644           /tmp/file.txt
14:23:45 12345  bash             RENAME       0 rename              /tmp/old.txt
14:23:45 12345  bash             READLINK    12 size=256            /etc/passwd
14:23:45 12345  bash             CLOSE        0 fd=3                close
```

**Columns:**
- **TIME**: Timestamp (HH:MM:SS)
- **PID**: Process ID
- **COMM**: Command name (truncated to 16 chars)
- **TYPE**: Syscall type (see Syscalls Traced list above)
- **RET**: Syscall return value (bytes for read/write, fd for open, 0 for success on directory ops)
- **ARGS**: Formatted syscall arguments (see [Syscall Arguments](#syscall-arguments) section below)
- **PATH**: File path (for path-based syscalls) or syscall name (for fd-based syscalls like fstat, fchmod, etc.)

##### Syscall Arguments

iosnoop captures and displays human-readable syscall arguments alongside the path and return value:

- **File Operations**: `flags=0xNNNN mode=0NNN` (for open/openat: permission bits and flags)
- **I/O Operations**: `fd=NNN size=NNN` (for read/write: file descriptor and buffer size)
- **Vector I/O Operations**: `fd=NNN iovcnt=NNN` (for readv/writev: file descriptor and iovec count) or `fd=NNN iovcnt=NNN offset=NNN` (for preadv/pwritev)
- **Positioned I/O Operations**: `fd=NNN size=NNN offset=NNN` (for pread64/pwrite64: file descriptor, buffer size, and file offset)
- **Directory Operations**: `mode=0NNN` (for mkdir: directory permission bits)
- **Deletion**: `dirfd=NNN flags=0xNNNN` (for unlinkat: descriptor and flags)
- **Rename**: `olddirfd=NNN newdirfd=NNN [flags=0xNNNN]` (directory context and optionally flags for renameat2)
- **Link Operations**: `dirfd=NNN flags=0xNNNN` (for linkat: directory context and flags)
- **Mount Operations**: `flags=0xNNNN` (mount/umount flags)
- **Ownership**: `uid=NNN gid=NNN` (for chown: user and group IDs)
- **Permissions**: `fd=NNN mode=0NNN` (for fchmod: file descriptor and new mode)
- **Truncation**: `length=NNN` (for truncate/ftruncate: target file size)

Example arguments:
- `open("/tmp/test.txt", flags=0x241 mode=0644)` → flags=0x241 mode=0644
- `read(fd=3, size=4096)` → fd=3 size=4096
- `readv(fd=3, iovcnt=2)` → fd=3 iovcnt=2
- `pread64(fd=3, size=4096, offset=1024)` → fd=3 size=4096 offset=1024
- `preadv(fd=3, iovcnt=2, offset=2048)` → fd=3 iovcnt=2 offset=2048
- `mkdir("/tmp/newdir", mode=0755)` → mode=0755
- `chown("/etc/config", uid=1000 gid=1000)` → uid=1000 gid=1000

#### Async I/O Syscalls

iosnoop also traces asynchronous I/O operations for both io_uring and libaio interfaces:

- **io_uring syscalls**:
  - `io_uring_enter`: `fd=NNN to_submit=NNN min_complete=NNN flags=0xNNNN`
  - `io_uring_setup`: `entries=NNN flags=0xNNNN`
  - `io_uring_register`: `fd=NNN opcode=NNN nr_args=NNN`
- **libaio syscalls**:
  - `io_setup`: `entries=NNN`
  - `io_submit`: `ctx_id=NNN nr=NNN`
  - `io_getevents`: `ctx_id=NNN min_nr=NNN nr=NNN`
  - `io_cancel`: `ctx_id=NNN`
  - `io_destroy`: `ctx_id=NNN`

Example async I/O output:
```
TIME     | PID     | COMM     | TYPE          | RET     | ARGS
14:32:15 | 12345   | app      | URING_ENTER   | 1       | fd=3 to_submit=10 min_complete=0 flags=0x0
14:32:15 | 12346   | app      | IO_SUBMIT     | 5       | ctx_id=139876543210 nr=5
```

### ioslower

```bash
sudo ./src/bin/ioslower                         # trace syscalls slower than 10ms (default)
sudo ./src/bin/ioslower -m 50                   # trace syscalls slower than 50ms
sudo ./src/bin/ioslower -m 5                    # trace syscalls slower than 5ms
sudo ./src/bin/ioslower -d 30                   # trace for 30 seconds
sudo ./src/bin/ioslower -m 100 -d 60            # 100ms threshold for 60 seconds
sudo ./src/bin/ioslower -v                      # verbose with BPF debug info
```

#### Output Format

```
TIME     PID    COMM             SYSCALL      LATENCY(ms) STATUS PATH
14:23:45 12345  bash             read           15.234      OK     read
14:23:45 12345  bash             write          42.567      OK     write
14:23:45 12345  bash             open           25.123      OK     /tmp/largefile.txt
14:23:45 12346  systemd          mkdir          100.456     OK     /var/run/newdir
14:23:45 12347  find             stat           18.789      OK     /tmp/file.txt
```

**Columns:**
- **TIME**: Timestamp (HH:MM:SS)
- **PID**: Process ID
- **COMM**: Command name (truncated to 16 chars)
- **SYSCALL**: Syscall name (open, read, write, mkdir, stat, etc.)
- **LATENCY(ms)**: Syscall duration in milliseconds (only syscalls exceeding threshold are shown)
- **STATUS**: OK for successful syscalls (ret >= 0), ERR for errors (ret < 0)
- **PATH**: File path (for path-based syscalls) or syscall name (for fd-based syscalls)

### aiosnoop

Trace asynchronous I/O operations via io_uring and libaio (AIO) syscalls.

```bash
sudo ./src/bin/aiosnoop                         # trace all async I/O syscalls
sudo ./src/bin/aiosnoop -v                      # verbose output
sudo ./src/bin/aiosnoop -d 30                   # trace for 30 seconds
```

#### Output Format

```
TIME     PID    COMM             SYSCALL          RET    ARGS
14:23:45 12345  myapp            uring_enter      3      fd=4 to_submit=2 min_complete=0 flags=0x0
14:23:45 12345  myapp            io_submit        2      ctx_id=140000 nr=2
14:23:45 12345  myapp            io_getevents     1      ctx_id=140000 min_nr=1 nr=10
14:23:45 12346  aioapp           uring_setup      4      entries=256
14:23:45 12347  oldaio           io_setup         0      nr_events=128
```

**Columns:**
- **TIME**: Timestamp (HH:MM:SS)
- **PID**: Process ID
- **COMM**: Command name (truncated to 16 chars)
- **SYSCALL**: Async I/O syscall name (uring_enter, io_submit, io_getevents, etc.)
- **RET**: Syscall return value (fd, number of operations, etc.; negative indicates error)
- **ARGS**: Syscall arguments with context (file descriptors, operation counts, flags, etc.)

#### Supported Syscalls

**io_uring (modern async I/O)**:
- `io_uring_enter` - submit I/O requests and/or wait for completions
- `io_uring_setup` - create new io_uring instance
- `io_uring_register` - register buffers/files for optimized access

**libaio (legacy AIO, x86/x64 only)**:
- `io_setup` - create AIO context
- `io_submit` - submit async I/O operations
- `io_getevents` - retrieve completion events
- `io_cancel` - cancel pending operations
- `io_destroy` - destroy AIO context
