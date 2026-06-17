// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "nfs_diag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int wakeup_data_size = 256;
const volatile __u8 filter_errors = 1;
const volatile __u8 filter_cmds = 1;

/* Use nfsstat4 enum in vmlinux.h for error code mapping */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ERROR_CODES); /* NFS error codes */
	__type(key, int); /* Error code */
	__type(value, __u8); /* Dummy value */
} allowlist_errors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NFS_COMMANDS); /* NFS commands */
    __type(key, __u16); /* Command code */
    __type(value, __u8); /* Dummy value */
} allowlist_cmds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096); /* should always be a multiple of the page size: can handle 174k events */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aodrb SEC(".maps");

static __always_inline long get_flags()
{
	long sz;
	if (!wakeup_data_size)
		return 0;
	sz = bpf_ringbuf_query(&aodrb, BPF_RB_AVAIL_DATA);
	return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

/** !Not ideal! The program still emits CORE relocations, but we are only
 * concerned about Azure VM images for now. Most of them expose the module
 * BTF. RHEL 8.10 runs the very old 4.18 kernel, which does not expose module
 * BTF, only vmlinux. But we are good because sunrpc is a part of the main
 * kernel, so rpc_task will always be relocated :)
 */

static int probe_entry(struct rpc_task *task)
{
    struct event *e;
    __u16 nfscommand;
    int retval;

    retval = -BPF_CORE_READ(task, tk_status);
    if (retval == 0) {
        return 0; // only trace failed requests to keep noise down, can always add a flag to include successes later
    }

    if (filter_errors) {
        __u8 *allowed_err = bpf_map_lookup_elem(&allowlist_errors, &retval);
        if (!allowed_err) {
            return 0;
        }
    }

    nfscommand = (__u16)BPF_CORE_READ(task, tk_msg.rpc_proc, p_statidx);
    if (filter_cmds) {
        __u8 *allowed_cmd = bpf_map_lookup_elem(&allowlist_cmds, &nfscommand);
        if (!allowed_cmd) {
            return 0;
        }
    }

    e = bpf_ringbuf_reserve(&aodrb, sizeof(*e), get_flags());
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cmd_end_time_ns = bpf_ktime_get_ns();
	e->metric.retval = retval;
	e->rqst_id = bpf_ntohl(BPF_CORE_READ(task, tk_rqstp, rq_xid));
	e->command = nfscommand;
	e->tool = NFSIOSNOOP;
	bpf_get_current_comm(&e->task, sizeof(e->task));
	bpf_ringbuf_submit(e, get_flags());

    return 0;
}
 
SEC("fentry/rpc_exit_task")
int BPF_PROG(rpc_done_entry, struct rpc_task *task)
{
	return probe_entry(task);
}

SEC("kprobe/rpc_exit_task")
int BPF_KPROBE(rpc_done_kprobe, struct rpc_task *task)
{
	return probe_entry(task);
}

