#!/usr/bin/env python3
"""CLI and end-to-end tests for smbiosnoop."""

import argparse
import ctypes
import ctypes.util
import os
import signal
import subprocess
import sys
import time
import uuid


RINGBUF_PINNED = "/sys/fs/bpf/aodrb"
SMB2_CREATE = 5
SMBIOSNOOP = 1
TASK_COMM_LEN = 16


class Metrics(ctypes.Union):
    _fields_ = [
        ("latency_ns", ctypes.c_ulonglong),
        ("retval", ctypes.c_int),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("command", ctypes.c_ushort),
        ("tool", ctypes.c_char),
        ("_pad", ctypes.c_char),
        ("cmd_end_time_ns", ctypes.c_ulonglong),
        ("rqst_id", ctypes.c_ulonglong),
        ("metric", Metrics),
        ("task", ctypes.c_char * TASK_COMM_LEN),
    ]


def assert_command(tool, args, expected_code, expected_text):
    """Run a CLI check and assert its exit status and combined output."""
    result = subprocess.run(
        [tool, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=5
    )
    output = result.stdout + result.stderr
    if result.returncode != expected_code or expected_text not in output:
        raise RuntimeError(
            f"CLI check failed: {tool} {' '.join(args)}\n"
            f"expected rc={expected_code} text={expected_text!r}\n"
            f"actual rc={result.returncode}\n{output}"
        )


def test_cli(tool):
    """Validate options that complete before attempting to load BPF."""
    assert_command(tool, ["--version"], 0, "smbiosnoop 0.1")
    assert_command(tool, [], 1, "Must specify at least one")
    assert_command(tool, ["--cmds", "20"], 64, "Invalid SMB command")
    assert_command(tool, ["--errors", "0"], 64, "Invalid NTSTATUS value")
    assert_command(tool, ["--errors", "0x100000000"], 64,
                   "Invalid NTSTATUS value")
    print("CLI tests passed")


def mount_fstype(path):
    """Return the filesystem type of the longest mount containing path."""
    path = os.path.realpath(path)
    best = ("", None)

    with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
        for line in mountinfo:
            left, right = line.rstrip().split(" - ", 1)
            mountpoint = left.split()[4].replace("\\040", " ")
            fstype = right.split()[0]
            if (path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")):
                if len(mountpoint) > len(best[0]):
                    best = (mountpoint, fstype)

    return best[1]


def wait_for_loader(process, timeout=5):
    """Wait until the loader pins its ring buffer or exits."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise RuntimeError(
                f"smbiosnoop exited during startup (rc={process.returncode})\n"
                f"{stderr}"
            )
        if os.path.exists(RINGBUF_PINNED):
            return
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for smbiosnoop ring buffer")


def test_cifs_error(tool, mount_path, timeout):
    """Assert that a missing-file lookup emits a failed SMB2 CREATE event."""
    if os.geteuid() != 0:
        raise RuntimeError("end-to-end test must run as root")
    if mount_fstype(mount_path) != "cifs":
        raise RuntimeError(f"{mount_path} is not on a CIFS mount")
    if os.path.exists(RINGBUF_PINNED):
        raise RuntimeError(f"refusing to replace existing {RINGBUF_PINNED}")

    process = subprocess.Popen(
        [tool, "--cmds", str(SMB2_CREATE), "--wakeupsize", "0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    map_fd = -1
    ring_buffer = None
    try:
        wait_for_loader(process)
        library = ctypes.CDLL(ctypes.util.find_library("bpf") or "libbpf.so")
        library.bpf_obj_get.argtypes = [ctypes.c_char_p]
        library.bpf_obj_get.restype = ctypes.c_int
        callback_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        )
        library.ring_buffer__new.argtypes = [
            ctypes.c_int, callback_type, ctypes.c_void_p, ctypes.c_void_p
        ]
        library.ring_buffer__new.restype = ctypes.c_void_p
        library.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        library.ring_buffer__poll.restype = ctypes.c_int
        library.ring_buffer__free.argtypes = [ctypes.c_void_p]

        captured = []

        def handle_event(_ctx, data, size):
            if size >= ctypes.sizeof(Event):
                event = ctypes.cast(data, ctypes.POINTER(Event)).contents
                captured.append((
                    event.tool[0],
                    event.command,
                    ctypes.c_uint32(event.metric.retval).value,
                ))
            return 0

        callback = callback_type(handle_event)
        map_fd = library.bpf_obj_get(RINGBUF_PINNED.encode())
        if map_fd < 0:
            raise RuntimeError("failed to open pinned smbiosnoop ring buffer")
        ring_buffer = library.ring_buffer__new(map_fd, callback, None, None)
        if not ring_buffer:
            raise RuntimeError("failed to create ring buffer consumer")

        missing = os.path.join(mount_path, f"smbiosnoop-missing-{uuid.uuid4()}")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                os.open(missing, os.O_RDONLY)
            except FileNotFoundError:
                pass

            result = library.ring_buffer__poll(ring_buffer, 250)
            if result < 0 and result != -4:
                raise RuntimeError(f"ring buffer polling failed: {result}")

            matches = [event for event in captured
                       if event[0] == SMBIOSNOOP and
                       event[1] == SMB2_CREATE and event[2] != 0]
            if matches:
                print(f"Captured SMB2 CREATE failure: NTSTATUS=0x{matches[0][2]:08x}")
                return

        raise RuntimeError(f"no failed SMB2 CREATE event captured; events={captured}")
    finally:
        if ring_buffer:
            library.ring_buffer__free(ring_buffer)
        if map_fd >= 0:
            os.close(map_fd)
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        try:
            os.unlink(RINGBUF_PINNED)
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Test smbiosnoop")
    parser.add_argument("--tool", default="./src/bin/smbiosnoop")
    parser.add_argument("--mount-path",
                        help="Existing CIFS mount used for the end-to-end test")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    tool = os.path.abspath(args.tool)
    test_cli(tool)
    if args.mount_path:
        test_cifs_error(tool, args.mount_path, args.timeout)
        print("smbiosnoop end-to-end test passed")
    else:
        print("CIFS end-to-end test skipped (provide --mount-path)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Test failed: {error}", file=sys.stderr)
        sys.exit(1)