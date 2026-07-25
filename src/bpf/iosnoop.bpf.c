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

/* Trace syscall: fstat */
SEC("tp/syscalls/sys_enter_fstat")
int trace_fstat_enter(struct trace_event_raw_sys_enter *ctx)
{
	/* fstat doesn't have filename, just fd */
	char fname[] = "fstat";
	__u64 id = bpf_get_current_pid_uid();
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_fstat")
int trace_fstat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	char fname[] = "fstat";
	emit_event(IO_FSTAT, ret, fname);
	bpf_map_delete_elem(&task_paths, &id);
	
	return 0;
}

/* Trace syscall: mkdir/mkdirat */
SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdir")
int trace_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_MKDIR, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_mkdirat")
int trace_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_mkdirat")
int trace_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_MKDIRAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: rmdir */
SEC("tp/syscalls/sys_enter_rmdir")
int trace_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_rmdir")
int trace_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_RMDIR, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: unlink/unlinkat */
SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_unlink")
int trace_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_UNLINK, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int trace_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_UNLINKAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: rename/renameat/renameat2 */
SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_RENAME, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat")
int trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_RENAMEAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_RENAMEAT2, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: mount/umount2 */
SEC("tp/syscalls/sys_enter_mount")
int trace_mount_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_mount")
int trace_mount_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_MOUNT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_umount2")
int trace_umount2_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_umount2")
int trace_umount2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_UMOUNT2, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: chmod/fchmod */
SEC("tp/syscalls/sys_enter_chmod")
int trace_chmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_chmod")
int trace_chmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_CHMOD, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchmod")
int trace_fchmod_enter(struct trace_event_raw_sys_enter *ctx)
{
	char fname[] = "fchmod";
	__u64 id = bpf_get_current_pid_uid();
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_fchmod")
int trace_fchmod_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	char fname[] = "fchmod";
	emit_event(IO_FCHMOD, ret, fname);
	bpf_map_delete_elem(&task_paths, &id);
	
	return 0;
}

/* Trace syscall: chown/fchown */
SEC("tp/syscalls/sys_enter_chown")
int trace_chown_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_chown")
int trace_chown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_CHOWN, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_fchown")
int trace_fchown_enter(struct trace_event_raw_sys_enter *ctx)
{
	char fname[] = "fchown";
	__u64 id = bpf_get_current_pid_uid();
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_fchown")
int trace_fchown_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	char fname[] = "fchown";
	emit_event(IO_FCHOWN, ret, fname);
	bpf_map_delete_elem(&task_paths, &id);
	
	return 0;
}

/* Trace syscall: truncate/ftruncate */
SEC("tp/syscalls/sys_enter_truncate")
int trace_truncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_truncate")
int trace_truncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_TRUNCATE, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_ftruncate")
int trace_ftruncate_enter(struct trace_event_raw_sys_enter *ctx)
{
	char fname[] = "ftruncate";
	__u64 id = bpf_get_current_pid_uid();
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_ftruncate")
int trace_ftruncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	char fname[] = "ftruncate";
	emit_event(IO_FTRUNCATE, ret, fname);
	bpf_map_delete_elem(&task_paths, &id);
	
	return 0;
}

/* Trace syscall: link/linkat */
SEC("tp/syscalls/sys_enter_link")
int trace_link_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_link")
int trace_link_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_LINK, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_linkat")
int trace_linkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_linkat")
int trace_linkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_LINKAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: symlink/symlinkat */
SEC("tp/syscalls/sys_enter_symlink")
int trace_symlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_symlink")
int trace_symlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_SYMLINK, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_symlinkat")
int trace_symlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_symlinkat")
int trace_symlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_SYMLINKAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

/* Trace syscall: readlink/readlinkat */
SEC("tp/syscalls/sys_enter_readlink")
int trace_readlink_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[0];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_readlink")
int trace_readlink_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_READLINK, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

SEC("tp/syscalls/sys_enter_readlinkat")
int trace_readlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	char *fname = (char *)ctx->args[1];
	bpf_map_update_elem(&task_paths, &id, fname, 0);
	
	return 0;
}

SEC("tp/syscalls/sys_exit_readlinkat")
int trace_readlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 id = bpf_get_current_pid_uid();
	long ret = ctx->ret;
	
	char **fname = bpf_map_lookup_elem(&task_paths, &id);
	if (fname) {
		emit_event(IO_READLINKAT, ret, *fname);
		bpf_map_delete_elem(&task_paths, &id);
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
