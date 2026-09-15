#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2026 Microsoft
#
# Consumer using libringbuf_shim.so for bulk event consumption (single copy
# into numpy).  This is the approach used by the AODv2 EventDispatcher.
#
# Usage:
#   1. Run the C loader first:  sudo ./smbslower [opts]
#   2. Then:                    sudo python3 shim_consumer.py
#   3. Detach:                  sudo python3 shim_consumer.py --detach [smb] [nfs]

import ctypes
import os
import signal
import sys

import numpy as np

# ---------------------------------------------------------------------------
# Load the ring buffer shim
# ---------------------------------------------------------------------------
_SHIM_DIR = os.path.join(os.path.dirname(__file__), "..", "bin")
_shim = ctypes.CDLL(os.path.join(_SHIM_DIR, "libringbuf_shim.so"))

_shim.rb_open.argtypes = [ctypes.c_char_p]
_shim.rb_open.restype = ctypes.c_void_p

_shim.rb_poll_into.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
]
_shim.rb_poll_into.restype = ctypes.c_int

_shim.rb_close.argtypes = [ctypes.c_void_p]
_shim.rb_close.restype = None

# ---------------------------------------------------------------------------
# Constants and event dtype (must match aod_diag.h)
# ---------------------------------------------------------------------------
TASK_COMM_LEN = 16
RINGBUF_PINNED = b"/sys/fs/bpf/aodrb"
MAX_BATCH = 2048

event_dtype = np.dtype(
    [
        ("pid", np.int32),
        ("command", np.uint16),
        ("tool", "S1"),
        ("_pad", "S1"),
        ("cmd_end_time_ns", np.uint64),
        ("rqst_id", np.uint64),
        ("metric_latency_ns", np.uint64),
        ("task", f"S{TASK_COMM_LEN}"),
    ],
    align=True,
)

# Pinned link paths (must match aod_diag.h)
_TOOL_LINKS = {
    "smb": [
        "/sys/fs/bpf/aod_smb_mid_alloc",
        "/sys/fs/bpf/aod_smb_mid_release",
    ],
    "nfs": [
        "/sys/fs/bpf/aod_nfs_seq_setup",
        "/sys/fs/bpf/aod_nfs_rpc_exit",
    ],
}


# ---------------------------------------------------------------------------
# Detach — unpin BPF links and (if nothing remains) the ring buffer.
# ---------------------------------------------------------------------------
def detach(tools=None):
    """Unpin BPF links for the given tools (list of 'smb'/'nfs', or None for all).
    Removes the shared ring buffer only when no links remain."""
    targets = list(tools) if tools else list(_TOOL_LINKS.keys())
    errors = 0

    for tool in targets:
        links = _TOOL_LINKS.get(tool)
        if not links:
            print(f"Unknown tool: {tool}", file=sys.stderr)
            errors += 1
            continue
        for path in links:
            try:
                os.unlink(path)
                print(f"  unpinned {path}")
            except FileNotFoundError:
                pass
            except OSError as e:
                print(f"  failed to unpin {path}: {e}", file=sys.stderr)
                errors += 1

    # Remove ring buffer only if no tool links remain
    remaining = [p for t, paths in _TOOL_LINKS.items()
                 if t not in targets for p in paths]
    if any(os.path.exists(p) for p in remaining):
        print(f"  ring buffer kept ({RINGBUF_PINNED.decode()}) — "
              "other tools still attached")
    else:
        try:
            os.unlink(RINGBUF_PINNED)
            print(f"  unpinned {RINGBUF_PINNED.decode()}")
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"  failed to unpin ring buffer: {e}", file=sys.stderr)
            errors += 1

    status = "with errors" if errors else "successfully"
    print(f"detach: completed {status}")
    return 1 if errors else 0


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
exiting = False


def _sig_handler(_sig, _frame):
    global exiting
    exiting = True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global exiting

    # Handle --detach [smb] [nfs]
    if "--detach" in sys.argv:
        idx = sys.argv.index("--detach")
        tools = sys.argv[idx + 1:] or None
        return detach(tools)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    ctx = _shim.rb_open(RINGBUF_PINNED)
    if not ctx:
        print(
            f"Failed to open pinned ring buffer at {RINGBUF_PINNED.decode()}. "
            "Is a loader (smbslower/nfsslower) running?",
            file=sys.stderr,
        )
        return 1

    print("consumer: polling ring buffer (Ctrl-C to stop) ...")
    try:
        while not exiting:
            buf = np.empty(MAX_BATCH, dtype=event_dtype)
            count = _shim.rb_poll_into(ctx, buf.ctypes.data, MAX_BATCH, 100)

            if count < 0 and count != -4:  # -4 == EINTR
                print(f"ring_buffer__poll error: {count}", file=sys.stderr)
                break

            for i in range(count):
                e = buf[i]
                task = e["task"].split(b"\x00", 1)[0].decode(errors="replace")
                prefix = (
                    f"pid={e['pid']:<7} task={task:<16} "
                    f"rqst_id={e['rqst_id']:<12} "
                    f"cmd={e['command']:<30}"
                )
                if e["tool"] == b"\x01":
                    status = int(e["metric_latency_ns"]) & 0xffffffff
                    print(f"{prefix} ntstatus=0x{status:08x}")
                elif e["tool"] == b"\x0b":
                    error = int(e["metric_latency_ns"]) & 0xffffffff
                    print(f"{prefix} error={error}")
                else:
                    lat_ms = e["metric_latency_ns"] / 1_000_000
                    print(f"{prefix} latency={lat_ms:.2f}ms")
    finally:
        _shim.rb_close(ctx)

    return 0


if __name__ == "__main__":
    sys.exit(main())
