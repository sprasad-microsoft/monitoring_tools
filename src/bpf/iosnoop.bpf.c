#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (256 * 1024)

/* Event types */
#define IO_OPEN		1
#define IO_OPENAT	2
#define IO_READ		3
#define IO_WRITE	4
#define IO_CLOSE	5
#define IO_STAT		6
#define IO_LSTAT	7
#define IO_FSTAT	8
#define IO_MKDIR	9
#define IO_MKDIRAT	10
#define IO_RMDIR	11
#define IO_UNLINK	12
#define IO_UNLINKAT	13
#define IO_RENAME	14
#define IO_RENAMEAT	15
#define IO_RENAMEAT2	16
#define IO_MOUNT	17
#define IO_UMOUNT2	18
#define IO_CHMOD	19
#define IO_FCHMOD	20
#define IO_CHOWN	21
#define IO_FCHOWN	22
#define IO_TRUNCATE	23
#define IO_FTRUNCATE	24
#define IO_LINK		25
#define IO_LINKAT	26
#define IO_SYMLINK	27
#define IO_SYMLINKAT	28
#define IO_READLINK	29
#define IO_READLINKAT	30
#define IO_PREAD64	31
#define IO_PWRITE64	32
#define IO_READV	33
#define IO_WRITEV	34
#define IO_PREADV	35
#define IO_PWRITEV	36
/* Async I/O syscalls */
#define IO_URING_ENTER	37
#define IO_URING_SETUP	38
#define IO_URING_REGISTER	39
#define IO_SETUP	40
#define IO_SUBMIT	41
#define IO_GETEVENTS	42
#define IO_CANCEL	43
#define IO_DESTROY	44
/* Memory mapping syscalls */
#define IO_MMAP	45
#define IO_MMAP2	46
#define IO_MUNMAP	47

struct iosnoop_event {
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
	char args[256];
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

/* Store syscall enter context (path + args) */
struct enter_state {
	char fname[256];
	__u64 args[6];
	__u8 type;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct enter_state);
} enter_ctx SEC(".maps");

static __always_inline int should_filter(__u32 dev_id)
{
	__u32 *filter_dev = bpf_map_lookup_elem(&mount_filter, &dev_id);
	if (!filter_dev)
		return 0;
	return 1;
}

/* Format syscall arguments as human-readable string */
static __always_inline void format_args(__u8 type, struct enter_state *state, char *args_str)
{
	/* Due to bpf_snprintf API incompatibilities with this kernel version,
	 * we use a simplified approach: just mark the argument type.
	 * Full formatting would require kernel-specific bpf_snprintf wrapping. */
	args_str[0] = '\0';
	
	if (!state)
		return;

	/* Single character type markers for now */
	switch (type) {
	case IO_OPEN:
		args_str[0] = '1';
		break;
	case IO_OPENAT:
		args_str[0] = '2';
		break;
	case IO_READ:
		args_str[0] = '3';
		break;
	case IO_WRITE:
		args_str[0] = '4';
		break;
	case IO_CLOSE:
		args_str[0] = '5';
		break;
	default:
		args_str[0] = '0';
	}
	args_str[1] = '\0';
}

static __always_inline void emit_event(__u8 type, __u32 ret, const char *fname, const char *args_str)
{
	struct iosnoop_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid & 0xffffffff;
	e->gid = uid_gid >> 32;
	e->type = type;
	e->ret = ret;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	if (fname)
		bpf_probe_read_kernel_str(&e->fname, sizeof(e->fname), (void *)fname);
	else
		e->fname[0] = '\0';

	if (args_str)
		__builtin_memcpy(&e->args, args_str, sizeof(e->args));
	else
		e->args[0] = '\0';

	bpf_ringbuf_submit(e, 0);
}

/* Trace syscall: open/openat */
SEC("tp/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_OPEN;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_OPEN, state, args_str);
		emit_event(IO_OPEN, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_OPENAT;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_OPENAT, state, args_str);
		emit_event(IO_OPENAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_READ;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"read");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_READ, state, args_str);
		emit_event(IO_READ, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_WRITE;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"write");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_WRITE, state, args_str);
		emit_event(IO_WRITE, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_CLOSE;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"close");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_close")
int trace_close_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_CLOSE, state, args_str);
		emit_event(IO_CLOSE, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_newstat")
int trace_stat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_STAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_newstat")
int trace_stat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_STAT, state, args_str);
		emit_event(IO_STAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_newlstat")
int trace_lstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_LSTAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_newlstat")
int trace_lstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_LSTAT, state, args_str);
		emit_event(IO_LSTAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_newfstat")
int trace_fstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_FSTAT;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"fstat");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_newfstat")
int trace_fstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_FSTAT, state, args_str);
		emit_event(IO_FSTAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_MKDIR;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdir")
int trace_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_MKDIR, state, args_str);
		emit_event(IO_MKDIR, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int trace_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_MKDIRAT;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdirat")
int trace_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_MKDIRAT, state, args_str);
		emit_event(IO_MKDIRAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int trace_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_RMDIR;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_rmdir")
int trace_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_RMDIR, state, args_str);
		emit_event(IO_RMDIR, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_UNLINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_unlink")
int trace_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_UNLINK, state, args_str);
		emit_event(IO_UNLINK, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_UNLINKAT;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int trace_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_UNLINKAT, state, args_str);
		emit_event(IO_UNLINKAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_RENAME;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_RENAME, state, args_str);
		emit_event(IO_RENAME, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_RENAMEAT;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat")
int trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_RENAMEAT, state, args_str);
		emit_event(IO_RENAMEAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_RENAMEAT2;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[4] = ctx->args[4];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_RENAMEAT2, state, args_str);
		emit_event(IO_RENAMEAT2, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_mount")
int trace_mount_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_MOUNT;
	state.args[3] = ctx->args[3];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mount")
int trace_mount_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_MOUNT, state, args_str);
		emit_event(IO_MOUNT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_umount")
int trace_umount2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_UMOUNT2;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_umount")
int trace_umount2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_UMOUNT2, state, args_str);
		emit_event(IO_UMOUNT2, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_CHMOD;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_chmod")
int trace_chmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_CHMOD, state, args_str);
		emit_event(IO_CHMOD, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchmod")
int trace_fchmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_FCHMOD;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"fchmod");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fchmod")
int trace_fchmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_FCHMOD, state, args_str);
		emit_event(IO_FCHMOD, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int trace_chown_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_CHOWN;
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_chown")
int trace_chown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_CHOWN, state, args_str);
		emit_event(IO_CHOWN, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchown")
int trace_fchown_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_FCHOWN;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"fchown");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fchown")
int trace_fchown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_FCHOWN, state, args_str);
		emit_event(IO_FCHOWN, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_truncate")
int trace_truncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_TRUNCATE;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_truncate")
int trace_truncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_TRUNCATE, state, args_str);
		emit_event(IO_TRUNCATE, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_ftruncate")
int trace_ftruncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_FTRUNCATE;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"ftruncate");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_ftruncate")
int trace_ftruncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_FTRUNCATE, state, args_str);
		emit_event(IO_FTRUNCATE, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_link")
int trace_link_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_LINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_link")
int trace_link_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_LINK, state, args_str);
		emit_event(IO_LINK, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_linkat")
int trace_linkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_LINKAT;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[4] = ctx->args[4];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_linkat")
int trace_linkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_LINKAT, state, args_str);
		emit_event(IO_LINKAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_symlink")
int trace_symlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_SYMLINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_symlink")
int trace_symlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_SYMLINK, state, args_str);
		emit_event(IO_SYMLINK, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_symlinkat")
int trace_symlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_SYMLINKAT;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_symlinkat")
int trace_symlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_SYMLINKAT, state, args_str);
		emit_event(IO_SYMLINKAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readlink")
int trace_readlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_READLINK;
	state.args[2] = ctx->args[2];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readlink")
int trace_readlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_READLINK, state, args_str);
		emit_event(IO_READLINK, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readlinkat")
int trace_readlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_READLINKAT;
	state.args[0] = ctx->args[0];
	state.args[3] = ctx->args[3];
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readlinkat")
int trace_readlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_READLINKAT, state, args_str);
		emit_event(IO_READLINKAT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pread64")
int trace_pread64_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_PREAD64;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"pread64");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pread64")
int trace_pread64_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_PREAD64, state, args_str);
		emit_event(IO_PREAD64, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pwrite64")
int trace_pwrite64_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_PWRITE64;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"pwrite64");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pwrite64")
int trace_pwrite64_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_PWRITE64, state, args_str);
		emit_event(IO_PWRITE64, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readv")
int trace_readv_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_READV;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"readv");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readv")
int trace_readv_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_READV, state, args_str);
		emit_event(IO_READV, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_WRITEV;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"writev");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_writev")
int trace_writev_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_WRITEV, state, args_str);
		emit_event(IO_WRITEV, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_preadv")
int trace_preadv_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_PREADV;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"preadv");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_preadv")
int trace_preadv_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_PREADV, state, args_str);
		emit_event(IO_PREADV, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pwritev")
int trace_pwritev_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_PWRITEV;
	state.args[0] = ctx->args[0];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"pwritev");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pwritev")
int trace_pwritev_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;
	
	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_PWRITEV, state, args_str);
		emit_event(IO_PWRITEV, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}
	
	return 0;
}

/* io_uring_enter */
SEC("tp/syscalls/sys_enter_io_uring_enter")
int trace_io_uring_enter_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_URING_ENTER;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_uring_enter");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_enter")
int trace_io_uring_enter_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_URING_ENTER, state, args_str);
		emit_event(IO_URING_ENTER, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_uring_setup */
SEC("tp/syscalls/sys_enter_io_uring_setup")
int trace_io_uring_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_URING_SETUP;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_uring_setup");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_setup")
int trace_io_uring_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_URING_SETUP, state, args_str);
		emit_event(IO_URING_SETUP, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_uring_register */
SEC("tp/syscalls/sys_enter_io_uring_register")
int trace_io_uring_register_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_URING_REGISTER;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[3] = ctx->args[3];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_uring_register");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_register")
int trace_io_uring_register_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_URING_REGISTER, state, args_str);
		emit_event(IO_URING_REGISTER, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_setup */
SEC("tp/syscalls/sys_enter_io_setup")
int trace_io_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_SETUP;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_setup");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_setup")
int trace_io_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_SETUP, state, args_str);
		emit_event(IO_SETUP, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_submit */
SEC("tp/syscalls/sys_enter_io_submit")
int trace_io_submit_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_SUBMIT;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_submit");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_submit")
int trace_io_submit_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_SUBMIT, state, args_str);
		emit_event(IO_SUBMIT, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_getevents */
SEC("tp/syscalls/sys_enter_io_getevents")
int trace_io_getevents_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_GETEVENTS;
	state.args[0] = ctx->args[0];
	state.args[1] = ctx->args[1];
	state.args[2] = ctx->args[2];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_getevents");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_getevents")
int trace_io_getevents_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_GETEVENTS, state, args_str);
		emit_event(IO_GETEVENTS, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_cancel */
SEC("tp/syscalls/sys_enter_io_cancel")
int trace_io_cancel_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_CANCEL;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_cancel");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_cancel")
int trace_io_cancel_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_CANCEL, state, args_str);
		emit_event(IO_CANCEL, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* io_destroy */
SEC("tp/syscalls/sys_enter_io_destroy")
int trace_io_destroy_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct enter_state state = {};

	state.type = IO_DESTROY;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"io_destroy");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_destroy")
int trace_io_destroy_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	long ret = ctx->ret;

	struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
	if (state) {
		char args_str[256];
		format_args(IO_DESTROY, state, args_str);
		emit_event(IO_DESTROY, ret, state->fname, args_str);
		bpf_map_delete_elem(&enter_ctx, &id);
	}

	return 0;
}

/* mmap */
SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
        __u64 id = bpf_get_current_pid_tgid();
        struct enter_state state = {};

        state.type = IO_MMAP;
        state.args[1] = ctx->args[1];  /* length */
        state.args[2] = ctx->args[2];  /* prot */
        state.args[3] = ctx->args[3];  /* flags */
        state.args[4] = ctx->args[4];  /* fd */
        bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"mmap");

        bpf_map_update_elem(&enter_ctx, &id, &state, 0);
        return 0;
}

SEC("tp/syscalls/sys_exit_mmap")
int trace_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
        __u64 id = bpf_get_current_pid_tgid();
        long ret = ctx->ret;

        struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
        if (state) {
                char args_str[256];
                format_args(IO_MMAP, state, args_str);
                emit_event(IO_MMAP, ret, state->fname, args_str);
                bpf_map_delete_elem(&enter_ctx, &id);
        }

        return 0;
}

/* munmap */
SEC("tp/syscalls/sys_enter_munmap")
int trace_munmap_enter(struct trace_event_raw_sys_enter *ctx)
{
        __u64 id = bpf_get_current_pid_tgid();
        struct enter_state state = {};

        state.type = IO_MUNMAP;
        state.args[1] = ctx->args[1];  /* length */
        bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"munmap");

        bpf_map_update_elem(&enter_ctx, &id, &state, 0);
        return 0;
}

SEC("tp/syscalls/sys_exit_munmap")
int trace_munmap_exit(struct trace_event_raw_sys_exit *ctx)
{
        __u64 id = bpf_get_current_pid_tgid();
        long ret = ctx->ret;

        struct enter_state *state = bpf_map_lookup_elem(&enter_ctx, &id);
        if (state) {
                char args_str[256];
                format_args(IO_MUNMAP, state, args_str);
                emit_event(IO_MUNMAP, ret, state->fname, args_str);
                bpf_map_delete_elem(&enter_ctx, &id);
        }

        return 0;
}


char LICENSE[] SEC("license") = "GPL";
