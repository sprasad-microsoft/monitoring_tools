// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 Microsoft */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "smb_diag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int wakeup_data_size = 256;
const volatile __u8 filter_errors = 1;
const volatile __u8 filter_cmds = 1;

struct smb3_cmd_err_args {
	__u64 common_fields;
	__u32 tid;
	__u32 __pad1;
	__u64 sesid;
	__u16 cmd;
	__u16 __pad2;
	__u32 __pad3;
	__u64 mid;
	__u32 status;
	int rc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SMB_STATUS_CODES);
	__type(key, __u32);
	__type(value, __u8);
} allowlist_errors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SMB_COMMANDS);
	__type(key, __u16);
	__type(value, __u8);
} allowlist_cmds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES * 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} aodrb SEC(".maps");

static __always_inline long get_flags(void)
{
	long size;

	if (!wakeup_data_size)
		return 0;
	size = bpf_ringbuf_query(&aodrb, BPF_RB_AVAIL_DATA);
	return size >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("tracepoint/cifs/smb3_cmd_err")
int trace_smb3_cmd_err(struct smb3_cmd_err_args *ctx)
{
	struct event *event;
	__u32 status = ctx->status;
	__u16 command = ctx->cmd;

	if (!status)
		return 0;
	if (filter_errors &&
	    !bpf_map_lookup_elem(&allowlist_errors, &status))
		return 0;
	if (filter_cmds &&
	    !bpf_map_lookup_elem(&allowlist_cmds, &command))
		return 0;

	event = bpf_ringbuf_reserve(&aodrb, sizeof(*event), get_flags());
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->cmd_end_time_ns = bpf_ktime_get_ns();
	event->metric.retval = (__s32)status;
	event->rqst_id = ctx->mid;
	event->command = command;
	event->tool = SMBIOSNOOP;
	bpf_get_current_comm(&event->task, sizeof(event->task));
	bpf_ringbuf_submit(event, get_flags());

	return 0;
}