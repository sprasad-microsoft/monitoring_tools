// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#include "cifs_btf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_endian_le.h"
#include "smb_diag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 min_lat_ns = 0;
const volatile int wakeup_data_size = 256;

struct smb3_cmd_done_args {
	__u64 common_fields;
	__u32 tid;
	__u32 __pad1;
	__u64 sesid;
	__u16 cmd;
	__u16 __pad2;
	__u32 __pad3;
	__u64 mid;
};

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

struct smb_trace_key {
	__u32 tid;
	__u64 sesid;
	__u64 mid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SMB_COMMANDS); /* SMB commands */
	__type(key, __u16); /* Command code */
	__type(value, __u8); /* Dummy value */
} denylist SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 24); /* can handle ~1.5x partial events */
	__type(key, struct mid_q_entry *);
	__type(value, struct smb_partial_event);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES * 24);
	__type(key, struct smb_trace_key);
	__type(value, struct smb_partial_event);
} trace_temp SEC(".maps");

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

/*
 * RHEL 8.10 provides vmlinux BTF but not BTF for cifs.ko. Consequently CO-RE
 * cannot relocate mid_q_entry fields for the function-probe fallback used by
 * --skip-tracepoints. These offsets were verified against the corresponding
 * cifs.ko binaries; later 4.18.0-553 errata changed the mid_q_entry layout.
 *
 * Fixed offsets are intentionally not treated as a generic RHEL ABI. The
 * userspace loader enables these programs only after matching both the exact
 * uname release and cifs module srcversion. An unknown module is rejected
 * rather than risking invalid reads or plausible but incorrect events.
 */
#define RHEL_810_MID_OFFSET 32
#define RHEL_810_COMMAND_OFFSET 124
#define RHEL_810_REFCOUNT_OFFSET 16
#define RHEL_810_553_134_MID_OFFSET 24
#define RHEL_810_553_134_COMMAND_OFFSET 40

static __always_inline int probe_exit(struct mid_q_entry *mid_struct)
{
	struct smb_partial_event *pe;
	struct smb_partial_event partial;
	struct event *e;

	pe = bpf_map_lookup_elem(&temp, &mid_struct);
	if (!pe) {
		return 0;
	}
	partial = *pe;

	__u64 now = bpf_ktime_get_ns();
	__u64 latency = now - partial.metric.latency_ns;
	bpf_map_delete_elem(&temp, &mid_struct);

	if (latency < min_lat_ns) {
		return 0;
	}

	e = bpf_ringbuf_reserve(&aodrb, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cmd_end_time_ns = now;
	e->metric.latency_ns = latency;
	e->rqst_id = partial.mid;
	e->command = partial.smbcommand;
	e->tool = SMBSLOWER;
	bpf_get_current_comm(&e->task, sizeof(e->task));
	bpf_ringbuf_submit(e, get_flags());

	return 0;
}

SEC("tracepoint/cifs/smb3_cmd_enter")
int trace_smb3_cmd_enter(struct smb3_cmd_done_args *ctx)
{
	struct smb_trace_key key = {
		.tid = ctx->tid,
		.sesid = ctx->sesid,
		.mid = ctx->mid,
	};
	struct smb_partial_event event = {
		.smbcommand = ctx->cmd,
	};

	if (bpf_map_lookup_elem(&denylist, &event.smbcommand))
		return 0;

	event.metric.latency_ns = bpf_ktime_get_ns();
	event.mid = ctx->mid;
	bpf_map_update_elem(&trace_temp, &key, &event, BPF_ANY);
	return 0;
}

static __always_inline int complete_trace_event(struct smb_trace_key *key)
{
	struct smb_partial_event *partial;
	struct smb_partial_event completed;
	struct event *event;
	__u64 now;
	__u64 latency;

	partial = bpf_map_lookup_elem(&trace_temp, key);
	if (!partial)
		return 0;
	completed = *partial;

	now = bpf_ktime_get_ns();
	latency = now - completed.metric.latency_ns;
	bpf_map_delete_elem(&trace_temp, key);
	if (latency < min_lat_ns)
		return 0;

	event = bpf_ringbuf_reserve(&aodrb, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->cmd_end_time_ns = now;
	event->metric.latency_ns = latency;
	event->rqst_id = completed.mid;
	event->command = completed.smbcommand;
	event->tool = SMBSLOWER;
	bpf_get_current_comm(&event->task, sizeof(event->task));
	bpf_ringbuf_submit(event, get_flags());

	return 0;
}

SEC("tracepoint/cifs/smb3_cmd_done")
int trace_smb3_cmd_done(struct smb3_cmd_done_args *ctx)
{
	struct smb_trace_key key = {
		.tid = ctx->tid,
		.sesid = ctx->sesid,
		.mid = ctx->mid,
	};

	return complete_trace_event(&key);
}

SEC("tracepoint/cifs/smb3_cmd_err")
int trace_smb3_cmd_err(struct smb3_cmd_err_args *ctx)
{
	struct smb_trace_key key = {
		.tid = ctx->tid,
		.sesid = ctx->sesid,
		.mid = ctx->mid,
	};

	return complete_trace_event(&key);
}

SEC("fexit/smb2_mid_entry_alloc")
int BPF_PROG(mid_alloc_fexit, void *shdr, void *server,
struct mid_q_entry *mid_struct)
{
	struct smb_partial_event e = {};
	e.smbcommand = bpf_le16_to_cpu(BPF_CORE_READ(mid_struct, command));

	__u8 *blocked = bpf_map_lookup_elem(&denylist, &e.smbcommand);
	if (blocked) {
		return 0;
	}

	e.metric.latency_ns = bpf_ktime_get_ns();
	e.mid = BPF_CORE_READ(mid_struct, mid);
	bpf_map_update_elem(&temp, &mid_struct, &e, BPF_NOEXIST);
	return 0;
}

SEC("kretprobe/smb2_mid_entry_alloc")
int BPF_KRETPROBE(mid_alloc_kretprobe)
{
	struct mid_q_entry *mid_struct = (struct mid_q_entry *)PT_REGS_RC(ctx);
	__u16 cmd;
	if (!mid_struct) {
		return 0;
	}

	/* No CORE */
	struct smb_partial_event e = {};
	bpf_probe_read_kernel(&cmd, sizeof(cmd), &mid_struct->command);
	e.smbcommand = bpf_le16_to_cpu(cmd);

	__u8 *blocked = bpf_map_lookup_elem(&denylist, &e.smbcommand);
	if (blocked) {
		return 0;
	}

	e.metric.latency_ns = bpf_ktime_get_ns();
	bpf_probe_read_kernel(&e.mid, sizeof(e.mid), &mid_struct->mid);
	bpf_map_update_elem(&temp, &mid_struct, &e, BPF_NOEXIST);
	return 0;
}

SEC("kretprobe/smb2_mid_entry_alloc")
int BPF_KRETPROBE(mid_alloc_rhel810_kretprobe)
{
	struct mid_q_entry *mid_struct = (struct mid_q_entry *)PT_REGS_RC(ctx);
	struct smb_partial_event e = {};
	__u16 cmd;

	if (!mid_struct)
		return 0;
	bpf_probe_read_kernel(&cmd, sizeof(cmd),
			      (char *)mid_struct + RHEL_810_COMMAND_OFFSET);
	e.smbcommand = bpf_le16_to_cpu(cmd);
	if (bpf_map_lookup_elem(&denylist, &e.smbcommand))
		return 0;
	e.metric.latency_ns = bpf_ktime_get_ns();
	bpf_probe_read_kernel(&e.mid, sizeof(e.mid),
			      (char *)mid_struct + RHEL_810_MID_OFFSET);
	bpf_map_update_elem(&temp, &mid_struct, &e, BPF_NOEXIST);
	return 0;
}

SEC("kretprobe/smb2_mid_entry_alloc")
int BPF_KRETPROBE(mid_alloc_rhel810_553_134_kretprobe)
{
	struct mid_q_entry *mid_struct = (struct mid_q_entry *)PT_REGS_RC(ctx);
	struct smb_partial_event e = {};
	__u16 cmd;

	if (!mid_struct)
		return 0;
	bpf_probe_read_kernel(&cmd, sizeof(cmd),
			      (char *)mid_struct + RHEL_810_553_134_COMMAND_OFFSET);
	e.smbcommand = bpf_le16_to_cpu(cmd);
	if (bpf_map_lookup_elem(&denylist, &e.smbcommand))
		return 0;
	e.metric.latency_ns = bpf_ktime_get_ns();
	bpf_probe_read_kernel(&e.mid, sizeof(e.mid),
			      (char *)mid_struct + RHEL_810_553_134_MID_OFFSET);
	bpf_map_update_elem(&temp, &mid_struct, &e, BPF_NOEXIST);
	return 0;
}

static __always_inline int release_kref(struct kref *refcount)
{
	const typeof(((struct mid_q_entry *)0)->refcount) *__mptr =
		(const typeof(((struct mid_q_entry *)0)->refcount) *)refcount;
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)__mptr - __builtin_preserve_field_info(((struct mid_q_entry *)0)->refcount, BPF_FIELD_BYTE_OFFSET));

	return probe_exit(mid_struct);
}

SEC("fentry/__release_mid")
int BPF_PROG(mid_release_kref_fentry, struct kref *refcount) {
	return release_kref(refcount);
}

SEC("kprobe/__release_mid")
int BPF_KPROBE(mid_release_kref_kprobe, struct kref *refcount) {
	return release_kref(refcount);
}

SEC("fentry/_cifs_mid_q_entry_release")
int BPF_PROG(mid_release_legacy_fentry, struct kref *refcount) {
	return release_kref(refcount);
}

SEC("kprobe/_cifs_mid_q_entry_release")
int BPF_KPROBE(mid_release_legacy_kprobe, struct kref *refcount) {
	return release_kref(refcount);
}

SEC("kprobe/_cifs_mid_q_entry_release")
int BPF_KPROBE(mid_release_rhel810_kprobe, struct kref *refcount) {
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)refcount - RHEL_810_REFCOUNT_OFFSET);

	return probe_exit(mid_struct);
}

SEC("kprobe/__release_mid")
int BPF_KPROBE(mid_release_rhel810_553_134_kprobe, struct kref *refcount) {
	struct mid_q_entry *mid_struct =
		(struct mid_q_entry *)((char *)refcount - RHEL_810_REFCOUNT_OFFSET);

	return probe_exit(mid_struct);
}

SEC("fentry/release_mid")
int BPF_PROG(mid_release_single_direct_fentry, struct mid_q_entry *midEntry) {
	return probe_exit(midEntry);
}

SEC("kprobe/release_mid")
int BPF_KPROBE(mid_release_single_direct_kprobe, struct mid_q_entry *midEntry) {
	return probe_exit(midEntry);
}

/* 6.19+: __release_mid(struct TCP_Server_Info *server, struct mid_q_entry *midEntry) */
SEC("fentry/__release_mid")
int BPF_PROG(mid_release_direct_fentry, void *server, struct mid_q_entry *midEntry) {
	return probe_exit(midEntry);
}

SEC("kprobe/__release_mid")
int BPF_KPROBE(mid_release_direct_kprobe, void *server, struct mid_q_entry *midEntry) {
	return probe_exit(midEntry);
}