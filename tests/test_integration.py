#!/usr/bin/env python3
"""
Integration test suite for iosnoop and ioslower.

Runs iosnoop/ioslower in background and validates that syscalls are being traced.

Usage:
    python3 test_integration.py --iosnoop <path/to/iosnoop>
    python3 test_integration.py --ioslower <path/to/ioslower>
    python3 test_integration.py --both <path/to/bin>
"""

import os
import sys
import tempfile
import subprocess
import time
import argparse
import shutil
from pathlib import Path


class TracingValidator:
    """Validates that syscalls are traced by iosnoop/ioslower."""
    
    def __init__(self, tool_path, is_ioslower=False):
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
    
    def setup(self):
        """Setup test environment."""
        self.test_dir = tempfile.mkdtemp(prefix="iosnoop_integration_")
        print(f"[{self.tool_name}] Test directory: {self.test_dir}")
    
    def cleanup(self):
        """Cleanup test environment."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        
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
            output = self.get_output()
            
            # Look for syscall name in output (case insensitive)
            if syscall_name.upper() in output.upper():
                return True
            
            time.sleep(0.1)
        
        return False


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


def run_integration_tests(tool_path, is_ioslower=False):
    """Run integration tests."""
    validator = TracingValidator(tool_path, is_ioslower)
    
    try:
        print("=" * 70)
        print(f"Integration Test Suite for {validator.tool_name}")
        print("=" * 70)
        
        validator.setup()
        validator.start_tracing()
        
        # Run test suites
        test_file_operations(validator)
        test_read_operations(validator)
        test_metadata_operations(validator)
        test_directory_operations(validator)
        test_link_operations(validator)
        test_vector_io_operations(validator)
        test_mmap_operations(validator)
        
        print("\n" + "=" * 70)
        print("Integration tests completed")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        validator.cleanup()


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
    
    args = parser.parse_args()
    
    if args.both:
        iosnoop_path = os.path.join(args.both, 'iosnoop')
        ioslower_path = os.path.join(args.both, 'ioslower')
        
        print("\n" + "=" * 70)
        print("Testing iosnoop")
        print("=" * 70)
        run_integration_tests(iosnoop_path, is_ioslower=False)
        
        print("\n\n" + "=" * 70)
        print("Testing ioslower")
        print("=" * 70)
        run_integration_tests(ioslower_path, is_ioslower=True)
    
    elif args.iosnoop:
        run_integration_tests(args.iosnoop, is_ioslower=False)
    
    elif args.ioslower:
        run_integration_tests(args.ioslower, is_ioslower=True)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
