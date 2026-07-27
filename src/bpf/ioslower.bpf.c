#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define RINGBUF_SIZE (256 * 1024)

/* Syscall types */
#define SC_OPEN		1
#define SC_OPENAT	2
#define SC_READ		3
#define SC_WRITE	4
#define SC_CLOSE	5
#define SC_STAT		6
#define SC_LSTAT	7
#define SC_FSTAT	8
#define SC_MKDIR	9
#define SC_MKDIRAT	10
#define SC_RMDIR	11
#define SC_UNLINK	12
#define SC_UNLINKAT	13
#define SC_RENAME	14
#define SC_RENAMEAT	15
#define SC_RENAMEAT2	16
#define SC_MOUNT	17
#define SC_UMOUNT2	18
#define SC_CHMOD	19
#define SC_FCHMOD	20
#define SC_CHOWN	21
#define SC_FCHOWN	22
#define SC_TRUNCATE	23
#define SC_FTRUNCATE	24
#define SC_LINK		25
#define SC_LINKAT	26
#define SC_SYMLINK	27
#define SC_SYMLINKAT	28
#define SC_READLINK	29
#define SC_READLINKAT	30
#define SC_PREAD64	31
#define SC_PWRITE64	32
#define SC_READV	33
#define SC_WRITEV	34
#define SC_PREADV	35
#define SC_PWRITEV	36
/* Async I/O syscalls */
#define SC_URING_ENTER	37
#define SC_URING_SETUP	38
#define SC_URING_REGISTER	39
#define SC_SETUP	40
#define SC_SUBMIT	41
#define SC_GETEVENTS	42
#define SC_CANCEL	43
#define SC_DESTROY	44

struct ioslower_event {
	__u64 ts;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u32 delta_us;
	__u8 type;
	__u8 __pad1;
	__u16 __pad2;
	__s32 ret;
	__u32 __pad3;
	char comm[16];
	char fname[256];
};

struct start_t {
	__u64 ts;
	__u32 type;
	char fname[256];
};

/* Ring buffer for events */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* Per-task state: record start time and syscall info */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct start_t);
} syscall_start SEC(".maps");

/* Configuration: latency threshold in microseconds */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} config SEC(".maps");

static __always_inline void emit_event(__u8 type, __u64 delta_ns, __s32 ret, const char *fname)
{
	struct ioslower_event *e;
	__u32 *threshold_us;
	__u32 zero = 0;

	/* Check threshold */
	threshold_us = bpf_map_lookup_elem(&config, &zero);
	if (!threshold_us)
		return;

	__u64 delta_us = delta_ns / 1000;
	if (delta_us < *threshold_us)
		return;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_uid() >> 32;
	e->uid = bpf_get_current_pid_uid() & 0xffffffff;
	e->gid = bpf_get_current_gid_uid() & 0xffffffff;
	e->type = type;
	e->ret = ret;
	e->delta_us = delta_us;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	if (fname)
		bpf_probe_read_kernel_str(&e->fname, sizeof(e->fname), (void *)fname);
	else
		e->fname[0] = '\0';

	bpf_ringbuf_submit(e, 0);
}

/* Trace open/openat */
SEC("tp/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_OPEN;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_OPEN, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_OPENAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_OPENAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace read/write */
SEC("tp/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_READ;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_READ, delta, ret, "read");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_WRITE;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_WRITE, delta, ret, "write");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace close */
SEC("tp/syscalls/sys_enter_close")
int trace_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_CLOSE;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_close")
int trace_close_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_CLOSE, delta, ret, "close");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace stat/lstat/fstat */
SEC("tp/syscalls/sys_enter_stat")
int trace_stat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_STAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_stat")
int trace_stat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_STAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_lstat")
int trace_lstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_LSTAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_lstat")
int trace_lstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_LSTAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fstat")
int trace_fstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_FSTAT;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fstat")
int trace_fstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_FSTAT, delta, ret, "fstat");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace mkdir/mkdirat/rmdir */
SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_MKDIR;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdir")
int trace_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_MKDIR, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int trace_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_MKDIRAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdirat")
int trace_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_MKDIRAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_rmdir")
int trace_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_RMDIR;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_rmdir")
int trace_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_RMDIR, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace unlink/unlinkat */
SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_UNLINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_unlink")
int trace_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_UNLINK, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_UNLINKAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int trace_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_UNLINKAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace rename/renameat/renameat2 */
SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_RENAME;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_RENAME, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_RENAMEAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat")
int trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_RENAMEAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_RENAMEAT2;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_RENAMEAT2, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace mount/umount2 */
SEC("tp/syscalls/sys_enter_mount")
int trace_mount_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_MOUNT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_mount")
int trace_mount_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_MOUNT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_umount2")
int trace_umount2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_UMOUNT2;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_umount2")
int trace_umount2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_UMOUNT2, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* Trace chmod/chown/truncate */
SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_CHMOD;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_chmod")
int trace_chmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_CHMOD, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_truncate")
int trace_truncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_TRUNCATE;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_truncate")
int trace_truncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_TRUNCATE, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchmod")
int trace_fchmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_FCHMOD;
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), (void *)"fchmod");

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fchmod")
int trace_fchmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_FCHMOD, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int trace_chown_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_CHOWN;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_chown")
int trace_chown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_CHOWN, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchown")
int trace_fchown_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_FCHOWN;
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), (void *)"fchown");

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_fchown")
int trace_fchown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_FCHOWN, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_ftruncate")
int trace_ftruncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_FTRUNCATE;
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), (void *)"ftruncate");

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_ftruncate")
int trace_ftruncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_FTRUNCATE, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_link")
int trace_link_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_LINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_link")
int trace_link_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_LINK, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_linkat")
int trace_linkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_LINKAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_linkat")
int trace_linkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_LINKAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_symlink")
int trace_symlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_SYMLINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_symlink")
int trace_symlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_SYMLINK, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_symlinkat")
int trace_symlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_SYMLINKAT;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_symlinkat")
int trace_symlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_SYMLINKAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readlink")
int trace_readlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_READLINK;
	char *fname = (char *)ctx->args[0];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readlink")
int trace_readlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_READLINK, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readlinkat")
int trace_readlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_READLINKAT;
	char *fname = (char *)ctx->args[1];
	bpf_probe_read_kernel_str(&start.fname, sizeof(start.fname), fname);

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readlinkat")
int trace_readlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_READLINKAT, delta, ret, start->fname);
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pread64")
int trace_pread64_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_PREAD64;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pread64")
int trace_pread64_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_PREAD64, delta, ret, "pread64");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pwrite64")
int trace_pwrite64_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_PWRITE64;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pwrite64")
int trace_pwrite64_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_PWRITE64, delta, ret, "pwrite64");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readv")
int trace_readv_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_READV;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_readv")
int trace_readv_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_READV, delta, ret, "readv");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_WRITEV;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_writev")
int trace_writev_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_WRITEV, delta, ret, "writev");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_preadv")
int trace_preadv_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_PREADV;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_preadv")
int trace_preadv_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_PREADV, delta, ret, "preadv");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_pwritev")
int trace_pwritev_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_PWRITEV;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_pwritev")
int trace_pwritev_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_PWRITEV, delta, ret, "pwritev");
		bpf_map_delete_elem(&syscall_start, &id);
	}
	
	return 0;
}

/* io_uring_enter */
SEC("tp/syscalls/sys_enter_io_uring_enter")
int trace_io_uring_enter_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_URING_ENTER;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_enter")
int trace_io_uring_enter_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_URING_ENTER, delta, ret, "io_uring_enter");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_uring_setup */
SEC("tp/syscalls/sys_enter_io_uring_setup")
int trace_io_uring_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_URING_SETUP;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_setup")
int trace_io_uring_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_URING_SETUP, delta, ret, "io_uring_setup");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_uring_register */
SEC("tp/syscalls/sys_enter_io_uring_register")
int trace_io_uring_register_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_URING_REGISTER;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_uring_register")
int trace_io_uring_register_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_URING_REGISTER, delta, ret, "io_uring_register");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_setup */
SEC("tp/syscalls/sys_enter_io_setup")
int trace_io_setup_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_SETUP;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_setup")
int trace_io_setup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_SETUP, delta, ret, "io_setup");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_submit */
SEC("tp/syscalls/sys_enter_io_submit")
int trace_io_submit_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_SUBMIT;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_submit")
int trace_io_submit_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_SUBMIT, delta, ret, "io_submit");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_getevents */
SEC("tp/syscalls/sys_enter_io_getevents")
int trace_io_getevents_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_GETEVENTS;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_getevents")
int trace_io_getevents_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_GETEVENTS, delta, ret, "io_getevents");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_cancel */
SEC("tp/syscalls/sys_enter_io_cancel")
int trace_io_cancel_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_CANCEL;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_cancel")
int trace_io_cancel_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_CANCEL, delta, ret, "io_cancel");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

/* io_destroy */
SEC("tp/syscalls/sys_enter_io_destroy")
int trace_io_destroy_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	struct start_t start = {};

	start.ts = bpf_ktime_get_ns();
	start.type = SC_DESTROY;
	start.fname[0] = '\0';

	bpf_map_update_elem(&syscall_start, &id, &start, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_io_destroy")
int trace_io_destroy_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;

	struct start_t *start = bpf_map_lookup_elem(&syscall_start, &id);
	if (start) {
		__u64 delta = bpf_ktime_get_ns() - start->ts;
		emit_event(SC_DESTROY, delta, ret, "io_destroy");
		bpf_map_delete_elem(&syscall_start, &id);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
