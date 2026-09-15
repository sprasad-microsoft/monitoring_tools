#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2026 Microsoft
#
# Sample consumer of events from the pinned BPF ring buffer at /sys/fs/bpf/aodrb
# In the final implementation, this will be integrated in the event dispatcher, which
# will consume from the ringbuf every x ms /1s and forward events to the configured sinks.
#
# Usage:
#   1. Run the C loader first:  sudo ./smbslower [opts]
#   2. Then:                    sudo python3 smbslower_consumer.py

import ctypes
import ctypes.util
import os
import signal
import sys

# ---------------------------------------------------------------------------
# libbpf ffi
# ---------------------------------------------------------------------------
_lib_path = ctypes.util.find_library("bpf")
if not _lib_path:
    _lib_path = "libbpf.so.1"
libbpf = ctypes.CDLL(_lib_path)

# ctypes for: int bpf_obj_get(const char *pathname)
libbpf.bpf_obj_get.restype = ctypes.c_int
libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]

# ctypes for our ringbuf callback: typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size)
RING_BUF_CB = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)

# ctypes for: struct ring_buffer *ring_buffer__new(int map_fd, ring_buffer_sample_fn cb,
#                                      void *ctx, const void *opts)
libbpf.ring_buffer__new.restype = ctypes.c_void_p
libbpf.ring_buffer__new.argtypes = [
    ctypes.c_int, RING_BUF_CB, ctypes.c_void_p, ctypes.c_void_p
]

# ctypes for: int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms)
libbpf.ring_buffer__poll.restype = ctypes.c_int
libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]

# ctypes for: void ring_buffer__free(struct ring_buffer *rb)
libbpf.ring_buffer__free.restype = None
libbpf.ring_buffer__free.argtypes = [ctypes.c_void_p]

# ---------------------------------------------------------------------------
# struct event  (matches src/include/aod_diag.h)
# ---------------------------------------------------------------------------
TASK_COMM_LEN = 16
RINGBUF_PINNED = b"/sys/fs/bpf/aodrb"

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

# ---------------------------------------------------------------------------
# Detach — unpin BPF links and (if nothing remains) the ring buffer. 
# In our case, the AODV2 daemon will handle it.
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
# Event callback
# ---------------------------------------------------------------------------
exiting = False


def _handle_event(_ctx, data, size):
    if size < ctypes.sizeof(Event):
        return 0
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    task = e.task.split(b"\x00", 1)[0].decode(errors="replace")
    cmd_name = e.command
    prefix = (f"pid={e.pid:<7} task={task:<16} rqst_id={e.rqst_id:<12} "
              f"cmd={cmd_name:<30}")
    if e.tool == b"\x01":
        status = ctypes.c_uint32(e.metric.retval).value
        print(f"{prefix} ntstatus=0x{status:08x}")
    elif e.tool == b"\x0b":
        print(f"{prefix} error={e.metric.retval}")
    else:
        lat_ms = e.metric.latency_ns / 1_000_000
        print(f"{prefix} latency={lat_ms:.2f}ms")
    return 0


# prevent GC of the ctypes callback by python - program holds a ref to the variable
_cb = RING_BUF_CB(_handle_event)


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

    map_fd = libbpf.bpf_obj_get(RINGBUF_PINNED)
    if map_fd < 0:
        print(
            f"Failed to open pinned ring buffer at {RINGBUF_PINNED.decode()}. "
            "Is a loader (smbslower/nfsslower) running?",
            file=sys.stderr,
        )
        return 1

    rb = libbpf.ring_buffer__new(map_fd, _cb, None, None)
    if not rb:
        print("ring_buffer__new failed", file=sys.stderr)
        return 1

    print("consumer: polling ring buffer (Ctrl-C to stop) ...")
    try:
        while not exiting:
            err = libbpf.ring_buffer__poll(rb, 100)  # 100 ms timeout
            if err < 0 and err != -4:  # -4 == EINTR
                print(f"ring_buffer__poll error: {err}", file=sys.stderr)
                break
    finally:
        libbpf.ring_buffer__free(rb)

    return 0


if __name__ == "__main__":
    sys.exit(main())
