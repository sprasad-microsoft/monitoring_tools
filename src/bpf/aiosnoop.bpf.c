#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (256 * 1024)

/* Async I/O syscall types */
#define AIO_URING_ENTER		1
#define AIO_URING_SETUP		2
#define AIO_URING_REGISTER	3
#define AIO_SETUP		4
#define AIO_SUBMIT		5
#define AIO_GETEVENTS		6
#define AIO_CANCEL		7
#define AIO_DESTROY		8

struct aio_event {
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
	char args[256];
};

/* Enter state for storing syscall arguments across enter/exit */
struct enter_state {
	__u8 type;
	char args[6];
	__u64 arg[6];
};

/* Ring buffer for events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* Per-task state: record syscall arguments */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct enter_state);
} enter_ctx SEC(".maps");

static __always_inline void format_args(__u8 type, struct enter_state *state, char *args_str)
{
	switch (type) {
	/* io_uring_enter(fd, to_submit, min_complete, flags) */
	case AIO_URING_ENTER: {
		__u64 fd = state->arg[0];
		__u64 to_submit = state->arg[1];
		__u64 min_complete = state->arg[2];
		__u64 flags = state->arg[3];
		bpf_snprintf(args_str, 256, "fd=%lld to_submit=%llu min_complete=%llu flags=0x%llx",
			     fd, to_submit, min_complete, flags);
		break;
	}
	/* io_uring_setup(entries, params) */
	case AIO_URING_SETUP: {
		__u64 entries = state->arg[0];
		bpf_snprintf(args_str, 256, "entries=%llu", entries);
		break;
	}
	/* io_uring_register(fd, opcode, arg, nr_args) */
	case AIO_URING_REGISTER: {
		__u64 fd = state->arg[0];
		__u64 opcode = state->arg[1];
		__u64 nr_args = state->arg[3];
		bpf_snprintf(args_str, 256, "fd=%lld opcode=%llu nr_args=%llu", fd, opcode, nr_args);
		break;
	}
	/* io_setup(nr_events, ctx_id_ptr) */
	case AIO_SETUP: {
		__u64 nr_events = state->arg[0];
		bpf_snprintf(args_str, 256, "nr_events=%llu", nr_events);
		break;
	}
	/* io_submit(ctx_id, nr, iocbs) */
	case AIO_SUBMIT: {
		__u64 ctx_id = state->arg[0];
		__u64 nr = state->arg[1];
		bpf_snprintf(args_str, 256, "ctx_id=%llu nr=%llu", ctx_id, nr);
		break;
	}
	/* io_getevents(ctx_id, min_nr, nr, events) */
	case AIO_GETEVENTS: {
		__u64 ctx_id = state->arg[0];
		__u64 min_nr = state->arg[1];
		__u64 nr = state->arg[2];
		bpf_snprintf(args_str, 256, "ctx_id=%llu min_nr=%llu nr=%llu", ctx_id, min_nr, nr);
		break;
	}
	/* io_cancel(ctx_id, iocb) */
	case AIO_CANCEL: {
		__u64 ctx_id = state->arg[0];
		bpf_snprintf(args_str, 256, "ctx_id=%llu", ctx_id);
		break;
	}
	/* io_destroy(ctx_id) */
	case AIO_DESTROY: {
		__u64 ctx_id = state->arg[0];
		bpf_snprintf(args_str, 256, "ctx_id=%llu", ctx_id);
		break;
	}
	default:
		bpf_snprintf(args_str, 256, "");
	}
}

static __always_inline void emit_event(__u8 type, __s32 ret, const char *args_str)
{
	struct aio_event *e;

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
	bpf_probe_read_kernel_str(&e->args, sizeof(e->args), (void *)args_str);

	bpf_ringbuf_submit(e, 0);
}

/* io_uring_enter */
SEC("tp/syscalls/sys_enter_io_uring_enter")
int trace_io_uring_enter_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_URING_ENTER;
	state.arg[0] = ctx->args[0];  /* fd */
	state.arg[1] = ctx->args[1];  /* to_submit */
	state.arg[2] = ctx->args[2];  /* min_complete */
	state.arg[3] = ctx->args[3];  /* flags */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_enter")
int trace_io_uring_enter_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_URING_ENTER, state, args_str);
		emit_event(AIO_URING_ENTER, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_uring_setup */
SEC("tp/syscalls/sys_enter_io_uring_setup")
int trace_io_uring_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_URING_SETUP;
	state.arg[0] = ctx->args[0];  /* entries */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_setup")
int trace_io_uring_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_URING_SETUP, state, args_str);
		emit_event(AIO_URING_SETUP, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_uring_register */
SEC("tp/syscalls/sys_enter_io_uring_register")
int trace_io_uring_register_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_URING_REGISTER;
	state.arg[0] = ctx->args[0];  /* fd */
	state.arg[1] = ctx->args[1];  /* opcode */
	state.arg[3] = ctx->args[3];  /* nr_args */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_register")
int trace_io_uring_register_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_URING_REGISTER, state, args_str);
		emit_event(AIO_URING_REGISTER, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_setup */
SEC("tp/syscalls/sys_enter_io_setup")
int trace_io_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_SETUP;
	state.arg[0] = ctx->args[0];  /* nr_events */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_setup")
int trace_io_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_SETUP, state, args_str);
		emit_event(AIO_SETUP, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_submit */
SEC("tp/syscalls/sys_enter_io_submit")
int trace_io_submit_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_SUBMIT;
	state.arg[0] = ctx->args[0];  /* ctx_id */
	state.arg[1] = ctx->args[1];  /* nr */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_submit")
int trace_io_submit_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_SUBMIT, state, args_str);
		emit_event(AIO_SUBMIT, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_getevents */
SEC("tp/syscalls/sys_enter_io_getevents")
int trace_io_getevents_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_GETEVENTS;
	state.arg[0] = ctx->args[0];  /* ctx_id */
	state.arg[1] = ctx->args[1];  /* min_nr */
	state.arg[2] = ctx->args[2];  /* nr */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_getevents")
int trace_io_getevents_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_GETEVENTS, state, args_str);
		emit_event(AIO_GETEVENTS, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_cancel */
SEC("tp/syscalls/sys_enter_io_cancel")
int trace_io_cancel_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_CANCEL;
	state.arg[0] = ctx->args[0];  /* ctx_id */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_cancel")
int trace_io_cancel_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_CANCEL, state, args_str);
		emit_event(AIO_CANCEL, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_destroy */
SEC("tp/syscalls/sys_enter_io_destroy")
int trace_io_destroy_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = AIO_DESTROY;
	state.arg[0] = ctx->args[0];  /* ctx_id */

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_destroy")
int trace_io_destroy_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(AIO_DESTROY, state, args_str);
		emit_event(AIO_DESTROY, ret, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
