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
#define IO_FSTAT	7
#define IO_MKDIR	8
#define IO_MKDIRAT	9
#define IO_RMDIR	10
#define IO_UNLINK	11
#define IO_UNLINKAT	12
#define IO_RENAME	13
#define IO_RENAMEAT	14
#define IO_RENAMEAT2	15
#define IO_MOUNT	16
#define IO_UMOUNT2	17
#define IO_CHMOD	18
#define IO_FCHMOD	19
#define IO_CHOWN	20
#define IO_FCHOWN	21
#define IO_TRUNCATE	22
#define IO_FTRUNCATE	23
#define IO_LINK		24
#define IO_LINKAT	25
#define IO_SYMLINK	26
#define IO_SYMLINKAT	27
#define IO_READLINK	28
#define IO_READLINKAT	29

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
	args_str[0] = '\0';
	
	if (!state)
		return;

	switch (type) {
	/* open(path, flags, mode) */
	case IO_OPEN: {
		__u64 flags = state->args[1];
		__u64 mode = state->args[2];
		bpf_snprintf(args_str, 256, "flags=0x%llx mode=0%o", flags, mode);
		break;
	}
	/* openat(dirfd, path, flags, mode) */
	case IO_OPENAT: {
		__u64 dirfd = state->args[0];
		__u64 flags = state->args[2];
		__u64 mode = state->args[3];
		bpf_snprintf(args_str, 256, "dirfd=%lld flags=0x%llx mode=0%o", dirfd, flags, mode);
		break;
	}
	/* read/write(fd, buf, size) */
	case IO_READ:
	case IO_WRITE: {
		__u64 fd = state->args[0];
		__u64 size = state->args[2];
		bpf_snprintf(args_str, 256, "fd=%lld size=%llu", fd, size);
		break;
	}
	/* close(fd) */
	case IO_CLOSE: {
		__u64 fd = state->args[0];
		bpf_snprintf(args_str, 256, "fd=%lld", fd);
		break;
	}
	/* chmod(path, mode) */
	case IO_CHMOD: {
		__u64 mode = state->args[1];
		bpf_snprintf(args_str, 256, "mode=0%o", mode);
		break;
	}
	/* stat/lstat(path) */
	case IO_STAT:
	case IO_LSTAT:
		bpf_snprintf(args_str, 256, "stat");
		break;
	/* fstat(fd, ...) */
	case IO_FSTAT: {
		__u64 fd = state->args[0];
		bpf_snprintf(args_str, 256, "fd=%lld", fd);
		break;
	}
	/* mkdir(path, mode) */
	case IO_MKDIR: {
		__u64 mode = state->args[1];
		bpf_snprintf(args_str, 256, "mode=0%o", mode);
		break;
	}
	/* mkdirat(dirfd, path, mode) */
	case IO_MKDIRAT: {
		__u64 dirfd = state->args[0];
		__u64 mode = state->args[2];
		bpf_snprintf(args_str, 256, "dirfd=%lld mode=0%o", dirfd, mode);
		break;
	}
	/* unlinkat(dirfd, path, flags) */
	case IO_UNLINKAT: {
		__u64 dirfd = state->args[0];
		__u64 flags = state->args[2];
		bpf_snprintf(args_str, 256, "dirfd=%lld flags=0x%llx", dirfd, flags);
		break;
	}
	/* rename(oldpath, newpath) */
	case IO_RENAME:
		bpf_snprintf(args_str, 256, "rename");
		break;
	/* renameat(olddirfd, oldpath, newdirfd, newpath) */
	case IO_RENAMEAT: {
		__u64 olddirfd = state->args[0];
		__u64 newdirfd = state->args[2];
		bpf_snprintf(args_str, 256, "olddirfd=%lld newdirfd=%lld", olddirfd, newdirfd);
		break;
	}
	/* renameat2(..., flags) */
	case IO_RENAMEAT2: {
		__u64 olddirfd = state->args[0];
		__u64 newdirfd = state->args[2];
		__u64 flags = state->args[4];
		bpf_snprintf(args_str, 256, "olddirfd=%lld newdirfd=%lld flags=0x%llx", olddirfd, newdirfd, flags);
		break;
	}
	/* mount(source, target, type, flags, data) */
	case IO_MOUNT: {
		__u64 flags = state->args[3];
		bpf_snprintf(args_str, 256, "flags=0x%llx", flags);
		break;
	}
	/* umount2(target, flags) */
	case IO_UMOUNT2: {
		__u64 flags = state->args[1];
		bpf_snprintf(args_str, 256, "flags=0x%llx", flags);
		break;
	}
	/* chown(path, uid, gid) */
	case IO_CHOWN: {
		__u64 uid = state->args[1];
		__u64 gid = state->args[2];
		bpf_snprintf(args_str, 256, "uid=%llu gid=%llu", uid, gid);
		break;
	}
	/* fchown(fd, uid, gid) */
	case IO_FCHOWN: {
		__u64 fd = state->args[0];
		__u64 uid = state->args[1];
		__u64 gid = state->args[2];
		bpf_snprintf(args_str, 256, "fd=%lld uid=%llu gid=%llu", fd, uid, gid);
		break;
	}
	/* truncate(path, length) */
	case IO_TRUNCATE: {
		__u64 length = state->args[1];
		bpf_snprintf(args_str, 256, "length=%llu", length);
		break;
	}
	/* ftruncate(fd, length) */
	case IO_FTRUNCATE: {
		__u64 fd = state->args[0];
		__u64 length = state->args[1];
		bpf_snprintf(args_str, 256, "fd=%lld length=%llu", fd, length);
		break;
	}
	/* link(oldpath, newpath) */
	case IO_LINK:
		bpf_snprintf(args_str, 256, "link");
		break;
	/* linkat(olddirfd, oldpath, newdirfd, newpath, flags) */
	case IO_LINKAT: {
		__u64 olddirfd = state->args[0];
		__u64 newdirfd = state->args[2];
		__u64 flags = state->args[4];
		bpf_snprintf(args_str, 256, "olddirfd=%lld newdirfd=%lld flags=0x%llx", olddirfd, newdirfd, flags);
		break;
	}
	/* symlink(target, linkpath) */
	case IO_SYMLINK:
		bpf_snprintf(args_str, 256, "symlink");
		break;
	/* symlinkat(target, newdirfd, linkpath) */
	case IO_SYMLINKAT: {
		__u64 newdirfd = state->args[1];
		bpf_snprintf(args_str, 256, "newdirfd=%lld", newdirfd);
		break;
	}
	/* readlink(path, buf, size) */
	case IO_READLINK: {
		__u64 size = state->args[2];
		bpf_snprintf(args_str, 256, "size=%llu", size);
		break;
	}
	/* readlinkat(dirfd, path, buf, size) */
	case IO_READLINKAT: {
		__u64 dirfd = state->args[0];
		__u64 size = state->args[3];
		bpf_snprintf(args_str, 256, "dirfd=%lld size=%llu", dirfd, size);
		break;
	}
	/* fchmod(fd, mode) */
	case IO_FCHMOD: {
		__u64 fd = state->args[0];
		__u64 mode = state->args[1];
		bpf_snprintf(args_str, 256, "fd=%lld mode=0%o", fd, mode);
		break;
	}
	default:
		bpf_snprintf(args_str, 256, "");
	}
}

static __always_inline void emit_event(__u8 type, __u32 ret, const char *fname, const char *args_str)
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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

SEC("tp/syscalls/sys_enter_stat")
int trace_stat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = IO_STAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_stat")
int trace_stat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
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

SEC("tp/syscalls/sys_enter_lstat")
int trace_lstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = IO_LSTAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_lstat")
int trace_lstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
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

SEC("tp/syscalls/sys_enter_fstat")
int trace_fstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = IO_FSTAT;
	state.args[0] = ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), (void *)"fstat");

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fstat")
int trace_fstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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

SEC("tp/syscalls/sys_enter_umount2")
int trace_umount2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct enter_state state = {};

	state.type = IO_UMOUNT2;
	state.args[1] = ctx->args[1];
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&state.fname, sizeof(state.fname), fname);

	bpf_map_update_elem(&enter_ctx, &id, &state, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_umount2")
int trace_umount2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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
	__u64 id = bpf_get_current_pid_uid();
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

char LICENSE[] SEC("license") = "GPL";
