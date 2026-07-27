# iosnoop and ioslower Test Suite

Comprehensive unit and integration tests for all syscalls traced by iosnoop and ioslower.

## Test Files

### `test_syscalls.c` - Unit Tests

C program that exercises all 48 syscalls covered by iosnoop and ioslower using direct
`syscall()` invocations. This allows testing every `*at()` variant, Linux AIO, and
io_uring without any language-level limitations.

**Categories covered:**

- **File Operations** (7): open, openat, read, write, close
- **File Metadata** (9): stat, lstat, fstat, chmod, fchmod, chown, fchown, truncate, ftruncate
- **Directory Operations** (3): mkdir, mkdirat, rmdir
- **File Deletion** (2): unlink, unlinkat
- **File Renaming** (3): rename, renameat, renameat2
- **Link Operations** (6): link, linkat, symlink, symlinkat, readlink, readlinkat
- **Vector I/O** (6): pread64, pwrite64, readv, writev, preadv, pwritev
- **Memory Mapping** (4): mmap (read), mmap (write), mmap (anon), munmap
- **Linux AIO** (5): io_setup, io_submit, io_getevents, io_cancel, io_destroy
- **io_uring** (3): io_uring_setup, io_uring_register, io_uring_enter
- **Mount/Unmount** (2): mount, umount2 (requires root / `--mount` flag)

**Build and run:**

```bash
# Build via make
make tests

# Or build manually and run
gcc -O0 -Wall -o tests/test_syscalls tests/test_syscalls.c
./tests/test_syscalls

# Include mount/umount2 (requires root)
sudo ./tests/test_syscalls --mount
```

### `test_integration.py` - Integration Tests

Runs iosnoop or ioslower in the background and validates that syscalls are being traced.

**Run integration tests:**

```bash
# Test iosnoop
python3 tests/test_integration.py --iosnoop ./src/bin/iosnoop

# Test ioslower
python3 tests/test_integration.py --ioslower ./src/bin/ioslower

# Test both
python3 tests/test_integration.py --both ./src/bin
```

The integration tests:
1. Start the tracer (iosnoop or ioslower) in the background
2. Execute various syscalls in a temporary directory
3. Parse tracer output to verify syscalls are detected
4. Display results showing which syscalls were successfully traced

## Test Coverage Matrix

| Syscall | Category | Unit Test | Integration |
|---------|----------|-----------|-------------|
| open | File Ops | ✓ | ✓ |
| openat | File Ops | ✓ | - |
| read | File Ops | ✓ | ✓ |
| write | File Ops | ✓ | ✓ |
| close | File Ops | ✓ | ✓ |
| stat | Metadata | ✓ | ✓ |
| lstat | Metadata | ✓ | - |
| fstat | Metadata | ✓ | - |
| chmod | Metadata | ✓ | ✓ |
| fchmod | Metadata | ✓ | - |
| chown | Metadata | ✓ | - |
| fchown | Metadata | ✓ | - |
| truncate | Metadata | ✓ | ✓ |
| ftruncate | Metadata | ✓ | - |
| mkdir | Directory | ✓ | ✓ |
| mkdirat | Directory | ✓ | - |
| rmdir | Directory | ✓ | - |
| unlink | Deletion | ✓ | - |
| unlinkat | Deletion | ✓ | - |
| rename | Rename | ✓ | - |
| renameat | Rename | ✓ | - |
| renameat2 | Rename | ✓ | - |
| link | Link | ✓ | - |
| linkat | Link | ✓ | - |
| symlink | Link | ✓ | ✓ |
| symlinkat | Link | ✓ | - |
| readlink | Link | ✓ | ✓ |
| readlinkat | Link | ✓ | - |
| pread64 | Vector I/O | ✓ | ✓ |
| pwrite64 | Vector I/O | ✓ | ✓ |
| readv | Vector I/O | ✓ | - |
| writev | Vector I/O | ✓ | - |
| preadv | Vector I/O | ✓ | - |
| pwritev | Vector I/O | ✓ | - |
| mmap | Memory Map | ✓ | ✓ |
| munmap | Memory Map | ✓ | ✓ |
| io_uring_setup | io_uring | ✓ | - |
| io_uring_register | io_uring | ✓ | - |
| io_uring_enter | io_uring | ✓ | - |
| io_setup | Linux AIO | ✓ | - |
| io_submit | Linux AIO | ✓ | - |
| io_getevents | Linux AIO | ✓ | - |
| io_cancel | Linux AIO | ✓ | - |
| io_destroy | Linux AIO | ✓ | - |
| mount | Mount | ✓ (root) | - |
| umount2 | Mount | ✓ (root) | - |

## Expected Output

### Unit Tests
```
======================================================================
Syscall coverage test for iosnoop / ioslower
Kernel: 6.x.y-generic
Tmpdir: /tmp/test_syscalls_XXXXXX
======================================================================

File operations
------------------------------------------------------------------
  ✓ open(O_CREAT)
  ✓ open(O_RDONLY)
  ...

======================================================================
Results:  48 passed,  0 failed,  1 skipped
======================================================================
```

### Integration Tests
```
======================================================================
Integration Test Suite for iosnoop
======================================================================
[iosnoop] Test directory: /tmp/iosnoop_integration_xyz123
[iosnoop] Starting: ./src/bin/iosnoop -d 30
[iosnoop] Tracer started (PID 12345)

[File Operations]
✓ OPEN traced
✓ WRITE traced
...
```

## Notes

- **Mount Tests**: Require `CAP_SYS_ADMIN`; pass `--mount` to `test_syscalls` when running as root
- **Integration Tests**: Require built iosnoop/ioslower binaries and BPF support (typically needs root)
- **Temporary Files**: All tests use `/tmp` with automatic cleanup
- **Container Compatibility**: Unit tests work in any container; integration tests need `--privileged`

## Dependencies

- **Unit tests**: `gcc`, standard C library (no extra packages needed)
- **Integration tests**: Python 3.6+, built iosnoop/ioslower binaries, BPF-capable kernel

## Troubleshooting

**Integration tests fail with "Operation not permitted":**
- Ensure BPF is enabled: `cat /proc/sys/kernel/unprivileged_bpf_disabled`
- May need to run with `sudo`

**Integration tests timeout:**
- Check binary is built: `ls src/bin/iosnoop src/bin/ioslower`
- Check file permissions on binary

## Adding New Tests

To add a unit test for a new syscall, add a test block in `test_syscalls.c` in the
appropriate section and call `PASS()`/`FAIL()`/`SKIP()` as appropriate.

To add an integration test, add a new `test_*` function in `test_integration.py`
and call it from `run_integration_tests()`.


## Test Files

### `test_syscalls.py` - Unit Tests

Tests all 46+ syscalls across multiple categories:

- **File Operations** (5 syscalls): open, openat, read, write, close
- **File Metadata** (8 syscalls): stat, lstat, fstat, chmod, fchmod, chown, fchown, truncate, ftruncate
- **Directory Operations** (3 syscalls): mkdir, mkdirat, rmdir
- **File Deletion** (2 syscalls): unlink, unlinkat
- **File Renaming** (3 syscalls): rename, renameat, renameat2
- **Link Operations** (6 syscalls): link, linkat, symlink, symlinkat, readlink, readlinkat
- **Vector I/O** (6 syscalls): pread64, pwrite64, readv, writev, preadv, pwritev
- **Memory Mapping** (3 syscalls): mmap, mmap2, munmap
- **Async I/O** (8 syscalls): io_uring_enter, io_uring_setup, io_uring_register, io_setup, io_submit, io_getevents, io_cancel, io_destroy
- **Mount/Unmount** (2 syscalls): mount, umount2 (skipped - requires CAP_SYS_ADMIN)

**Run unit tests:**

```bash
# Run all tests
python3 tests/test_syscalls.py

# Run with pytest
pytest tests/test_syscalls.py -v

# Run specific test class
pytest tests/test_syscalls.py::TestFileOperations -v

# Run specific test
pytest tests/test_syscalls.py::TestFileOperations::test_open_create -v
```

### `test_integration.py` - Integration Tests

Runs iosnoop or ioslower in the background and validates that syscalls are being traced.

**Run integration tests:**

```bash
# Test iosnoop
python3 tests/test_integration.py --iosnoop ./src/bin/iosnoop

# Test ioslower  
python3 tests/test_integration.py --ioslower ./src/bin/ioslower

# Test both
python3 tests/test_integration.py --both ./src/bin
```

The integration tests:
1. Start the tracer (iosnoop or ioslower) in background
2. Execute various syscalls in a temporary directory
3. Parse tracer output to verify syscalls are detected
4. Display results showing which syscalls were successfully traced

## Test Coverage Matrix

| Syscall | Category | Unit Test | Integration |
|---------|----------|-----------|------------|
| open | File Ops | ✓ | ✓ |
| openat | File Ops | ✓ | - |
| read | File Ops | ✓ | ✓ |
| write | File Ops | ✓ | ✓ |
| close | File Ops | ✓ | ✓ |
| stat | Metadata | ✓ | ✓ |
| lstat | Metadata | ✓ | - |
| fstat | Metadata | ✓ | - |
| chmod | Metadata | ✓ | ✓ |
| fchmod | Metadata | ✓ | - |
| chown | Metadata | ✓ | - |
| fchown | Metadata | ✓ | - |
| truncate | Metadata | ✓ | ✓ |
| ftruncate | Metadata | ✓ | - |
| mkdir | Directory | ✓ | ✓ |
| mkdirat | Directory | ✓ | - |
| rmdir | Directory | ✓ | - |
| unlink | Deletion | ✓ | - |
| unlinkat | Deletion | ✓ | - |
| rename | Rename | ✓ | - |
| renameat | Rename | ✓ | - |
| renameat2 | Rename | ✓ | - |
| link | Link | ✓ | - |
| linkat | Link | ✓ | - |
| symlink | Link | ✓ | ✓ |
| symlinkat | Link | ✓ | - |
| readlink | Link | ✓ | ✓ |
| readlinkat | Link | ✓ | - |
| pread64 | Vector I/O | ✓ | ✓ |
| pwrite64 | Vector I/O | ✓ | ✓ |
| readv | Vector I/O | ✓ | - |
| writev | Vector I/O | ✓ | - |
| preadv | Vector I/O | ✓ | - |
| pwritev | Vector I/O | ✓ | - |
| mmap | Memory Map | ✓ | ✓ |
| mmap2 | Memory Map | ✓ | - |
| munmap | Memory Map | ✓ | ✓ |
| io_uring_enter | Async I/O | ✓ | - |
| io_uring_setup | Async I/O | ✓ | - |
| io_uring_register | Async I/O | ✓ | - |
| io_setup | Async I/O | ✓ | - |
| io_submit | Async I/O | ✓ | - |
| io_getevents | Async I/O | ✓ | - |
| io_cancel | Async I/O | ✓ | - |
| io_destroy | Async I/O | ✓ | - |
| mount | Mount | ✓ | - |
| umount2 | Mount | ✓ | - |

## Expected Output

### Unit Tests
```
======================================================================
Testing all syscalls covered by iosnoop and ioslower
======================================================================

Tests for basic file operations.
----------------------------------------------------------------------
✓ open(O_CREAT) syscall executed
✓ open(O_RDONLY) syscall executed
✓ open(O_APPEND) syscall executed
✓ read() and write() syscalls executed
✓ close() syscall executed
✓ openat() syscall executed
...
======================================================================
Results: 60+ passed, 0 failed
======================================================================
```

### Integration Tests
```
======================================================================
Integration Test Suite for iosnoop
======================================================================
[iosnoop] Test directory: /tmp/iosnoop_integration_xyz123
[iosnoop] Starting: ./src/bin/iosnoop -d 30
[iosnoop] Output: /tmp/iosnoop_integration_xyz123/iosnoop_output.txt
[iosnoop] Tracer started (PID 12345)

[File Operations]
✓ OPEN traced
✓ WRITE traced
✓ CLOSE traced

[Read Operations]
✓ READ traced

[Metadata Operations]
✓ STAT traced
✓ CHMOD traced
✓ TRUNCATE traced
...
```

## Notes

- **Async I/O Tests**: Skipped in unit tests unless io_uring or libaio is available
- **Mount Tests**: Require CAP_SYS_ADMIN capability
- **Integration Tests**: Run the actual iosnoop/ioslower binaries, require BPF support
- **Temporary Files**: All tests use `/tmp` with automatic cleanup
- **Container Compatibility**: Tests should work in Docker/container environments

## Dependencies

- Python 3.6+
- pytest (for pytest mode)
- Running tests requires syscall permissions
- Integration tests require built iosnoop/ioslower binaries

## Troubleshooting

**Integration tests fail with "Operation not permitted":**
- Ensure BPF is enabled: `cat /proc/sys/kernel/unprivileged_bpf_disabled`
- May need to run with `sudo`

**Unit tests fail on async I/O:**
- io_uring or libaio not available on this system
- Tests skip gracefully

**Integration tests timeout:**
- Tools may not be installed or not in PATH
- Check file permissions on binary

## Adding New Tests

To add tests for a new syscall:

1. Add test method to appropriate class in `test_syscalls.py`:
   ```python
   def test_my_syscall(self):
       """Test my_syscall() syscall."""
       # Execute syscall
       result = my_operation()
       assert result  # Validate
       print("✓ my_syscall() syscall executed")
   ```

2. Add integration test in `test_integration.py`:
   ```python
   def test_my_syscall_operations(validator):
       """Test my_syscall."""
       # Execute syscall
       # Validate with validator.validate_syscall("MY_SYSCALL")
   ```

3. Run tests to verify
