# iosnoop and ioslower Tests

The test suite has two layers:

- `test_syscalls.c` executes the filesystem operations used to validate both tools.
- `test_integration.py` runs the real eBPF binaries around that workload and fails if a
  tracer cannot start, the workload fails, or a required operation class is absent.

The end-to-end checks cover the operation classes emitted by the current VFS probes:
open, read, write, create, stat, fchmod, truncate, mkdir, rmdir, unlink, rename,
link, symlink, readlink, readv, writev, fallocate, getdents, mmap, munmap, and
fcntl locking. Syscall variants such as `openat`, `renameat2`, `preadv`, and
`pwritev` are exercised by the workload but intentionally collapse into their VFS
operation class in tracer output.

## Build and run the workload

```bash
make tests
```

This builds and runs `tests/test_syscalls`. Mount and unmount calls are skipped by
default because they require `CAP_SYS_ADMIN`.

## Run end-to-end tests

Build the tracers and workload:

```bash
make iosnoop ioslower tests/test_syscalls
```

Run both tracers against an isolated tmpfs:

```bash
sudo python3 tests/test_integration.py \
  --both ./src/bin \
  --use-test-syscalls \
  --test-syscalls-bin ./tests/test_syscalls \
  --test-syscalls-target-dir /tmp \
  --test-syscalls-tmpfs
```

To test on an existing filesystem without mounting tmpfs, omit
`--test-syscalls-tmpfs`. The target directory also becomes the mount-filter path.

Test one tracer with `--iosnoop ./src/bin/iosnoop` or
`--ioslower ./src/bin/ioslower` instead of `--both`.

Add `--test-syscalls-mount` to include mount and unmount workload calls. This is
separate from `--test-syscalls-tmpfs`, which controls test isolation.

## Requirements

- GCC and Python 3
- Clang, bpftool, libbpf, and libelf development dependencies to build the tools
- A BPF-capable kernel with BTF matching the VFS function signatures used by the
  probes
- Root or equivalent BPF capabilities for end-to-end execution

The runner returns a nonzero status for setup errors, tracer load or attach errors,
workload failures, and missing operation classes, so it can be used directly in CI.

## Test smbiosnoop

Run deterministic CLI validation without a share:

```bash
python3 tests/test_smbiosnoop.py --tool ./src/bin/smbiosnoop
```

Run the end-to-end test against an existing CIFS mount. The test starts the real
eBPF loader, requests a missing path, and requires a failed SMB2 CREATE event with
a nonzero NTSTATUS value:

```bash
sudo python3 tests/test_smbiosnoop.py \
  --tool ./src/bin/smbiosnoop \
  --mount-path /mnt/smb
```

The end-to-end test refuses to replace an existing `/sys/fs/bpf/aodrb` pin.