#!/usr/bin/env python3
"""
Integration test suite for iosnoop and ioslower.

Runs iosnoop/ioslower in background and validates that syscalls are being traced.

Usage:
    python3 test_integration.py --iosnoop <path/to/iosnoop>
    python3 test_integration.py --ioslower <path/to/ioslower>
    python3 test_integration.py --both <path/to/bin>
    python3 test_integration.py --iosnoop ./src/bin/iosnoop \
        --use-test-syscalls --test-syscalls-bin ./tests/test_syscalls \
        --test-syscalls-target-dir /tmp
"""

import os
import sys
import tempfile
import subprocess
import time
import argparse
import shutil
from pathlib import Path


class TmpfsTestMount:
    """Create an isolated tmpfs mount for test_syscalls integration runs."""

    def __init__(self, base_dir=None):
        self.base_dir = os.path.abspath(base_dir) if base_dir else "/tmp"
        self.mount_path = None
        self.mounted = False

    def setup(self):
        """Create and mount a tmpfs-backed test directory."""
        self.mount_path = tempfile.mkdtemp(prefix="iosnoop_mount_", dir=self.base_dir)
        subprocess.run(
            ["mount", "-t", "tmpfs", "tmpfs", self.mount_path],
            check=True,
            capture_output=True,
            text=True,
        )
        self.mounted = True
        print(f"[test_syscalls] Mounted tmpfs at: {self.mount_path}")
        return self.mount_path

    def cleanup(self):
        """Unmount and remove the temporary test mount."""
        if self.mounted and self.mount_path:
            subprocess.run(
                ["umount", self.mount_path],
                check=True,
                capture_output=True,
                text=True,
            )
            self.mounted = False

        if self.mount_path and os.path.exists(self.mount_path):
            shutil.rmtree(self.mount_path)


class TracingValidator:
    """Validates that syscalls are traced by iosnoop/ioslower."""
    
    def __init__(self, tool_path, is_ioslower=False, output_copy_path=None, mount_path=None):
        """
        Initialize validator.
        
        Args:
            tool_path: Path to iosnoop or ioslower binary
            is_ioslower: True if testing ioslower, False for iosnoop
        """
        self.tool_path = tool_path
        self.is_ioslower = is_ioslower
        self.tool_name = "ioslower" if is_ioslower else "iosnoop"
        self.test_dir = None
        self.proc = None
        self.output_copy_path = output_copy_path
        self.mount_path = mount_path
    
    def setup(self):
        """Setup test environment."""
        self.test_dir = tempfile.mkdtemp(prefix="iosnoop_integration_")
        print(f"[{self.tool_name}] Test directory: {self.test_dir}")
    
    def cleanup(self):
        """Cleanup test environment."""
        self.stop_tracing()
        self.cleanup_test_dir()

    def stop_tracing(self):
        """Stop the tracer process if it is running."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def cleanup_test_dir(self):
        """Remove temporary test directory."""
        
        if self.test_dir and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def start_tracing(self):
        """Start iosnoop/ioslower in background."""
        if not os.path.exists(self.tool_path):
            raise FileNotFoundError(f"{self.tool_path} not found")
        
        output_file = os.path.join(self.test_dir, f"{self.tool_name}_output.txt")
        
        cmd = [self.tool_path, "-d", "30"]
        if self.is_ioslower:
            cmd += ["-m", "0"]  # No latency threshold: capture all syscalls
            if self.mount_path:
                cmd += ["-p", self.mount_path]
        elif self.mount_path:
            cmd += ["-m", self.mount_path]
        
        print(f"[{self.tool_name}] Starting: {' '.join(cmd)}")
        print(f"[{self.tool_name}] Output: {output_file}")
        
        with open(output_file, 'w') as f:
            self.proc = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True
            )
        
        time.sleep(1)  # Give tracer time to start
        
        if self.proc.poll() is not None:
            with open(output_file, 'r') as f:
                error = f.read()
            raise RuntimeError(f"{self.tool_name} failed to start:\n{error}")
        
        self.output_file = output_file
        print(f"[{self.tool_name}] Tracer started (PID {self.proc.pid})")
    
    def get_output(self):
        """Get tracer output."""
        if not os.path.exists(self.output_file):
            return ""
        
        with open(self.output_file, 'r') as f:
            return f.read()

    def captured_operations(self):
        """Return set of operation/syscall names from tracer output table."""
        output = self.get_output()
        operations = set()

        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            if ":" not in fields[0]:
                continue

            operations.add(fields[3].upper())

        return operations
    
    def validate_syscall(self, syscall_name, timeout=5):
        """
        Validate that a syscall is traced.
        
        Args:
            syscall_name: Name of syscall to look for (e.g., "open", "OPEN")
            timeout: Max time to wait for syscall to appear
        
        Returns:
            True if syscall found in output, False otherwise
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            operations = self.captured_operations()
            if syscall_name.upper() in operations:
                return True
            
            time.sleep(0.1)
        
        return False

    def wait_for_operations(self, required, timeout=5):
        """Wait for the tracer to drain all required operation classes."""
        deadline = time.time() + timeout
        captured = set()

        while time.time() < deadline:
            captured = self.captured_operations()
            if set(required) <= captured:
                break
            time.sleep(0.1)

        return captured


def test_file_operations(validator):
    """Test file operation syscalls."""
    print("\n[File Operations]")
    
    test_file = os.path.join(validator.test_dir, "test.txt")
    
    # open + write + close
    with open(test_file, 'w') as f:
        f.write("test data")
    
    syscalls = ["OPEN", "WRITE", "CLOSE"]
    for syscall in syscalls:
        if validator.validate_syscall(syscall):
            print(f"✓ {syscall} traced")
        else:
            print(f"✗ {syscall} NOT traced")


def test_read_operations(validator):
    """Test read syscalls."""
    print("\n[Read Operations]")
    
    test_file = os.path.join(validator.test_dir, "read_test.txt")
    with open(test_file, 'w') as f:
        f.write("x" * 4096)
    
    with open(test_file, 'r') as f:
        data = f.read()
    
    if validator.validate_syscall("READ"):
        print(f"✓ READ traced")
    else:
        print(f"✗ READ NOT traced")


def test_metadata_operations(validator):
    """Test metadata syscalls."""
    print("\n[Metadata Operations]")
    
    test_file = os.path.join(validator.test_dir, "metadata_test.txt")
    with open(test_file, 'w') as f:
        f.write("data")
    
    # stat
    os.stat(test_file)
    if validator.validate_syscall("STAT"):
        print(f"✓ STAT traced")
    else:
        print(f"✗ STAT NOT traced")
    
    # chmod
    os.chmod(test_file, 0o755)
    if validator.validate_syscall("CHMOD"):
        print(f"✓ CHMOD traced")
    else:
        print(f"✗ CHMOD NOT traced")
    
    # truncate
    os.truncate(test_file, 10)
    if validator.validate_syscall("TRUNCATE"):
        print(f"✓ TRUNCATE traced")
    else:
        print(f"✗ TRUNCATE NOT traced")


def test_directory_operations(validator):
    """Test directory syscalls."""
    print("\n[Directory Operations]")
    
    new_dir = os.path.join(validator.test_dir, "subdir")
    os.mkdir(new_dir)
    
    if validator.validate_syscall("MKDIR"):
        print(f"✓ MKDIR traced")
    else:
        print(f"✗ MKDIR NOT traced")


def test_link_operations(validator):
    """Test link syscalls."""
    print("\n[Link Operations]")
    
    test_file = os.path.join(validator.test_dir, "link_test.txt")
    with open(test_file, 'w') as f:
        f.write("data")
    
    symlink = os.path.join(validator.test_dir, "link.txt")
    os.symlink(test_file, symlink)
    
    if validator.validate_syscall("SYMLINK"):
        print(f"✓ SYMLINK traced")
    else:
        print(f"✗ SYMLINK NOT traced")
    
    os.readlink(symlink)
    if validator.validate_syscall("READLINK"):
        print(f"✓ READLINK traced")
    else:
        print(f"✗ READLINK NOT traced")


def test_vector_io_operations(validator):
    """Test vector I/O syscalls."""
    print("\n[Vector I/O Operations]")
    
    test_file = os.path.join(validator.test_dir, "vector_test.bin")
    with open(test_file, 'wb') as f:
        f.write(b"X" * 4096)
    
    # pread64
    fd = os.open(test_file, os.O_RDONLY)
    os.pread(fd, 10, 100)
    os.close(fd)
    
    if validator.validate_syscall("PREAD"):
        print(f"✓ PREAD64 traced")
    else:
        print(f"✗ PREAD64 NOT traced")
    
    # pwrite64
    fd = os.open(test_file, os.O_WRONLY)
    os.pwrite(fd, b"TEST", 50)
    os.close(fd)
    
    if validator.validate_syscall("PWRITE"):
        print(f"✓ PWRITE64 traced")
    else:
        print(f"✗ PWRITE64 NOT traced")


def test_mmap_operations(validator):
    """Test memory mapping syscalls."""
    print("\n[Memory Mapping Operations]")
    
    test_file = os.path.join(validator.test_dir, "mmap_test.bin")
    with open(test_file, 'wb') as f:
        f.write(b"A" * 4096)
    
    import mmap
    
    with open(test_file, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            data = m[:10]
    
    if validator.validate_syscall("MMAP"):
        print(f"✓ MMAP traced")
    else:
        print(f"✗ MMAP NOT traced")
    
    if validator.validate_syscall("MUNMAP"):
        print(f"✓ MUNMAP traced")
    else:
        print(f"✗ MUNMAP NOT traced")


def run_test_syscalls_workload(validator, test_syscalls_bin, target_dir=None, run_mount=False):
    """Run the C syscall coverage test as the integration workload."""
    print("\n[test_syscalls workload]")

    cmd = [test_syscalls_bin]
    if target_dir:
        cmd += ["--target-dir", target_dir]
    if run_mount:
        cmd += ["--mount"]

    print(f"[{validator.tool_name}] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)

    print("[test_syscalls] Summary:")
    for line in proc.stdout.splitlines():
        if line.startswith("Results:") or line.startswith("Tmpdir:"):
            print(f"  {line}")

    if proc.returncode != 0:
        raise RuntimeError(
            f"test_syscalls failed (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )


def required_test_syscalls(validator):
    """Return every operation class emitted for the C workload."""
    return [
        "OPEN", "READ", "WRITE", "CREATE", "STAT", "FCHMOD",
        "TRUNCATE", "MKDIR", "RMDIR", "UNLINK", "RENAME", "LINK",
        "SYMLINK", "READLINK", "READV", "WRITEV", "FALLOCATE",
        "GETDENTS", "MMAP", "MUNMAP", "LOCK_FCNTL",
    ]


def run_integration_tests(
    tool_path,
    is_ioslower=False,
    output_copy_path=None,
    mount_path=None,
    use_test_syscalls=False,
    test_syscalls_bin=None,
    test_syscalls_target_dir=None,
    test_syscalls_mount=False,
):
    """Run integration tests."""
    validator = TracingValidator(
        tool_path,
        is_ioslower,
        output_copy_path=output_copy_path,
        mount_path=mount_path,
    )
    
    try:
        print("=" * 70)
        print(f"Integration Test Suite for {validator.tool_name}")
        print("=" * 70)
        
        validator.setup()
        validator.start_tracing()

        if use_test_syscalls:
            if not test_syscalls_bin:
                raise ValueError("--test-syscalls-bin is required with --use-test-syscalls")

            run_test_syscalls_workload(
                validator,
                test_syscalls_bin,
                target_dir=test_syscalls_target_dir,
                run_mount=test_syscalls_mount,
            )

            expected = required_test_syscalls(validator)
            captured = validator.wait_for_operations(expected)

            print("\n[Required Operation Validation]")
            missing = []
            for operation in expected:
                if operation in captured:
                    print(f"✓ {operation} traced")
                else:
                    print(f"✗ {operation} NOT traced")
                    missing.append(operation)

            if missing:
                raise RuntimeError(
                    f"{validator.tool_name} missed {len(missing)} required "
                    f"operations: {', '.join(missing)}"
                )
        else:
            # Legacy Python-based workload mode
            test_file_operations(validator)
            test_read_operations(validator)
            test_metadata_operations(validator)
            test_directory_operations(validator)
            test_link_operations(validator)
            test_vector_io_operations(validator)
            test_mmap_operations(validator)
        
        print("\n" + "=" * 70)
        print("Integration tests passed")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        validator.stop_tracing()

        if validator.output_copy_path:
            try:
                output = validator.get_output()
                parent = Path(validator.output_copy_path).parent
                parent.mkdir(parents=True, exist_ok=True)
                with open(validator.output_copy_path, "w") as f:
                    f.write(output)
                print(f"[{validator.tool_name}] Saved output copy: {validator.output_copy_path}")
            except Exception as e:
                print(f"[{validator.tool_name}] Failed to save output copy: {e}")
        validator.cleanup_test_dir()


def resolve_test_syscalls_paths(args):
    """Resolve effective workload and mount-filter paths for test_syscalls runs."""
    tmpfs_mount = None
    target_dir = args.test_syscalls_target_dir

    if args.test_syscalls_tmpfs:
        base_dir = target_dir or "/tmp"
        tmpfs_mount = TmpfsTestMount(base_dir)
        target_dir = tmpfs_mount.setup()

    iosnoop_mount_path = args.iosnoop_mount_path or target_dir
    ioslower_mount_path = args.ioslower_mount_path or target_dir

    return tmpfs_mount, target_dir, iosnoop_mount_path, ioslower_mount_path


def resolve_mount_path(explicit_mount_path, use_test_syscalls, test_syscalls_target_dir):
    """Resolve effective mount filter path for the tracing tool."""
    if explicit_mount_path:
        return explicit_mount_path

    if use_test_syscalls:
        if test_syscalls_target_dir:
            return os.path.abspath(test_syscalls_target_dir)

        return "/tmp"

    return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Integration test suite for iosnoop and ioslower"
    )
    parser.add_argument('--iosnoop', type=str, 
                       help='Path to iosnoop binary')
    parser.add_argument('--ioslower', type=str,
                       help='Path to ioslower binary')
    parser.add_argument('--both', type=str,
                       help='Path to bin directory (tests both tools)')
    parser.add_argument('--save-iosnoop-output', type=str,
                       help='Persist iosnoop captured output to this file')
    parser.add_argument('--save-ioslower-output', type=str,
                       help='Persist ioslower captured output to this file')
    parser.add_argument('--iosnoop-mount-path', type=str,
                       help='Mount path filter for iosnoop capture')
    parser.add_argument('--ioslower-mount-path', type=str,
                       help='Mount path filter for ioslower capture')
    parser.add_argument('--use-test-syscalls', action='store_true',
                       help='Drive integration workload by running tests/test_syscalls')
    parser.add_argument('--test-syscalls-bin', type=str, default='./tests/test_syscalls',
                       help='Path to test_syscalls binary (used with --use-test-syscalls)')
    parser.add_argument('--test-syscalls-target-dir', type=str,
                       help='Parent directory for test_syscalls temporary directory')
    parser.add_argument('--test-syscalls-tmpfs', action='store_true',
                       help='Create an isolated tmpfs for the workload (requires CAP_SYS_ADMIN)')
    parser.add_argument('--test-syscalls-mount', action='store_true',
                       help='Pass --mount to test_syscalls (requires root/CAP_SYS_ADMIN)')
    
    args = parser.parse_args()

    tmpfs_mount = None

    try:
        tmpfs_mount, test_syscalls_target_dir, iosnoop_mount_path, ioslower_mount_path = resolve_test_syscalls_paths(args)
    
        if args.both:
            iosnoop_path = os.path.join(args.both, 'iosnoop')
            ioslower_path = os.path.join(args.both, 'ioslower')
        
            print("\n" + "=" * 70)
            print("Testing iosnoop")
            print("=" * 70)
            iosnoop_passed = run_integration_tests(
                iosnoop_path,
                is_ioslower=False,
                output_copy_path=args.save_iosnoop_output,
                mount_path=iosnoop_mount_path,
                use_test_syscalls=args.use_test_syscalls,
                test_syscalls_bin=args.test_syscalls_bin,
                test_syscalls_target_dir=test_syscalls_target_dir,
                test_syscalls_mount=args.test_syscalls_mount,
            )
        
            print("\n\n" + "=" * 70)
            print("Testing ioslower")
            print("=" * 70)
            ioslower_passed = run_integration_tests(
                ioslower_path,
                is_ioslower=True,
                output_copy_path=args.save_ioslower_output,
                mount_path=ioslower_mount_path,
                use_test_syscalls=args.use_test_syscalls,
                test_syscalls_bin=args.test_syscalls_bin,
                test_syscalls_target_dir=test_syscalls_target_dir,
                test_syscalls_mount=args.test_syscalls_mount,
            )
            if not iosnoop_passed or not ioslower_passed:
                sys.exit(1)

        elif args.iosnoop:
            if not run_integration_tests(
                args.iosnoop,
                is_ioslower=False,
                output_copy_path=args.save_iosnoop_output,
                mount_path=iosnoop_mount_path,
                use_test_syscalls=args.use_test_syscalls,
                test_syscalls_bin=args.test_syscalls_bin,
                test_syscalls_target_dir=test_syscalls_target_dir,
                test_syscalls_mount=args.test_syscalls_mount,
            ):
                sys.exit(1)

        elif args.ioslower:
            if not run_integration_tests(
                args.ioslower,
                is_ioslower=True,
                output_copy_path=args.save_ioslower_output,
                mount_path=ioslower_mount_path,
                use_test_syscalls=args.use_test_syscalls,
                test_syscalls_bin=args.test_syscalls_bin,
                test_syscalls_target_dir=test_syscalls_target_dir,
                test_syscalls_mount=args.test_syscalls_mount,
            ):
                sys.exit(1)

        else:
            parser.print_help()
            sys.exit(1)
    finally:
        if tmpfs_mount:
            tmpfs_mount.cleanup()


if __name__ == '__main__':
    main()
