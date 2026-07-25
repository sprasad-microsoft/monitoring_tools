#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (256 * 1024)

/* Event types */
#define IO_OPEN		1
#define IO_READ		2
#define IO_WRITE	3
#define IO_CLOSE	4
#define IO_STAT		5
#define IO_LSTAT	6

struct io_event {
	__u64 ts;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u8 type;
	__u8 __pad1;
	__u16 __pad2;
	__s32 ret;
	__u32 __pad3;
	char comm[16];
	char fname[256];
};

/* Ring buffer for events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* Configuration map: mount_dev -> 1 (1 means filter enabled for this device) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mount_filter SEC(".maps");

/* Per-task state for capturing syscall arguments */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, char[256]);
} task_paths SEC(".maps");

static __always_inline int should_filter(__u32 dev_id)
{
	__u32 *filter_dev = bpf_map_lookup_elem(&mount_filter, &dev_id);
	if (!filter_dev)
		return 0;
	return 1;
}

static __always_inline void emit_event(__u8 type, __u32 ret, const char *fname)
{
	struct io_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_uid() >> 32;
	e->uid = bpf_get_current_pid_uid() & 0xffffffff;
	e->gid = bpf_get_current_gid_uid() & 0xffffffff;
	e->type = type;
	e->ret = ret;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	if (fname)
		bpf_probe_read_kernel_str(&e->fname, sizeof(e->fname), (void *)fname);
	else
		e->fname[0] = '\0';

	bpf_ringbuf_submit(e, 0);
}

/* Trace syscall: open/openat */
SEC("tp/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	__u32 pid = id >> 32;
	
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_OPEN, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	
	/* args[1] is the pathname for openat */
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_OPEN, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: read */
SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	__u32 pid = id >> 32;
	__u32 fd = ctx->args[0];
	
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	if (ret > 0) {
		/* Only emit on successful read with data */
		char fname[] = "read";
		emit_event(IO_READ, ret, fname);
	}
	return 0;
}

/* Trace syscall: write */
SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	__u32 fd = ctx->args[0];
	__u32 count = ctx->args[2];
	
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	if (ret > 0) {
		char fname[] = "write";
		emit_event(IO_WRITE, ret, fname);
	}
	return 0;
}

/* Trace syscall: close */
SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	__u32 fd = ctx->args[0];
	
	return 0;
}

SEC("tp/syscalls/sys_exit_close")
int trace_close_exit(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	char fname[] = "close";
	emit_event(IO_CLOSE, ret, fname);
	
	return 0;
}

/* Trace syscall: stat/lstat */
SEC("tp/syscalls/sys_enter_stat")
int trace_stat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_stat")
int trace_stat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_STAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_lstat")
int trace_lstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_lstat")
int trace_lstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_LSTAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
