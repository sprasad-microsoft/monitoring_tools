#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct renamedata___legacy {
	struct inode *new_dir;
	struct dentry *new_dentry;
} __attribute__((preserve_access_index));

#define RINGBUF_SIZE (4 * 1024 * 1024)

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
#define IO_MMAP		45
#define IO_MUNMAP	47
#define IO_CREATE	48
#define IO_FALLOCATE	49
#define IO_GETDENTS	50
#define IO_LOCK_FCNTL	51
#define IO_LOCK_FLOCK	52

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

struct mount_filter_cfg {
	__u32 enabled;
	__u32 dev_major;
	__u32 dev_minor;
};

struct op_ctx {
	__u8 type;
	__u8 __pad1;
	__u16 __pad2;
	__u32 dev;
	char fname[96];
	char args[128];
};

struct op_key {
	__u64 id;
	__u32 type;
	__u32 __pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* Key 0: mount filter configuration (enabled + target s_dev). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mount_filter_cfg);
} mount_filter_cfg SEC(".maps");

/* Per-thread context from VFS entry to exit probe. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct op_key);
	__type(value, struct op_ctx);
} op_state SEC(".maps");

/*
 * mmap address -> s_dev mapping so that vm_munmap can apply mount filtering.
 * Key: (u32 pid << 32) | (mapped_addr >> 12).  Value: s_dev.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} vma_dev_map SEC(".maps");

static __always_inline bool pass_mount_filter(__u32 dev)
{
	__u32 key = 0;
	struct mount_filter_cfg *cfg;
	__u32 dev_major;
	__u32 dev_minor;

	cfg = bpf_map_lookup_elem(&mount_filter_cfg, &key);
	if (!cfg || !cfg->enabled)
		return true;

	if (!dev)
		return true;

	dev_major = dev >> 20;
	dev_minor = dev & ((1U << 20) - 1);

	return cfg->dev_major == dev_major && cfg->dev_minor == dev_minor;
}

static __always_inline __u32 dev_from_path(struct path *path)
{
	struct dentry *dentry;
	struct super_block *sb;
	__u32 dev = 0;

	if (!path)
		return 0;

	bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
	if (!dentry)
		return 0;

	bpf_core_read(&sb, sizeof(sb), &dentry->d_sb);
	if (!sb)
		return 0;

	bpf_core_read(&dev, sizeof(dev), &sb->s_dev);
	return dev;
}

static __always_inline __u32 dev_from_file(struct file *file)
{
	struct dentry *dentry;
	struct super_block *sb;
	__u32 dev = 0;

	if (!file)
		return 0;

	bpf_core_read(&dentry, sizeof(dentry), &file->f_path.dentry);
	if (!dentry)
		return 0;

	bpf_core_read(&sb, sizeof(sb), &dentry->d_sb);
	if (!sb)
		return 0;

	bpf_core_read(&dev, sizeof(dev), &sb->s_dev);
	return dev;
}

static __always_inline __u32 dev_from_dentry(struct dentry *dentry)
{
	struct super_block *sb;
	__u32 dev = 0;

	if (!dentry)
		return 0;

	bpf_core_read(&sb, sizeof(sb), &dentry->d_sb);
	if (!sb)
		return 0;

	bpf_core_read(&dev, sizeof(dev), &sb->s_dev);
	return dev;
}

static __always_inline __u32 dev_from_inode(struct inode *inode)
{
	struct super_block *sb;
	__u32 dev = 0;

	if (!inode)
		return 0;

	bpf_core_read(&sb, sizeof(sb), &inode->i_sb);
	if (!sb)
		return 0;

	bpf_core_read(&dev, sizeof(dev), &sb->s_dev);
	return dev;
}

static __always_inline __u32 configured_mount_dev(void)
{
	__u32 key = 0;
	struct mount_filter_cfg *cfg;

	cfg = bpf_map_lookup_elem(&mount_filter_cfg, &key);
	if (!cfg || !cfg->enabled)
		return 0;

	return (cfg->dev_major << 20) | cfg->dev_minor;
}

static __always_inline void read_dentry_name(struct dentry *dentry, char *dst,
				      int dst_sz)
{
	const unsigned char *name;

	if (!dentry || dst_sz <= 0) {
		dst[0] = '\0';
		return;
	}

	bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
	if (!name || bpf_probe_read_kernel_str(dst, dst_sz, name) < 0)
		dst[0] = '\0';
}

static __always_inline void read_path_name(struct path *path, char *dst, int dst_sz)
{
	struct dentry *dentry;

	if (!path) {
		dst[0] = '\0';
		return;
	}

	bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
	read_dentry_name(dentry, dst, dst_sz);
}

static __always_inline void read_file_name(struct file *file, char *dst, int dst_sz)
{
	struct dentry *dentry;

	if (!file) {
		dst[0] = '\0';
		return;
	}

	bpf_core_read(&dentry, sizeof(dentry), &file->f_path.dentry);
	read_dentry_name(dentry, dst, dst_sz);
}

static __always_inline int append_lit(char *dst, int pos, int max, const char *lit)
{
	int i;

	for (i = 0; i < 40; i++) {
		if (pos >= max - 1 || !lit[i])
			break;
		dst[pos++] = lit[i];
	}

	dst[pos] = '\0';
	return pos;
}

static __always_inline int append_u64_dec(char *dst, int pos, int max, __u64 v)
{
	char tmp[21];
	int i = 0;

	if (pos >= max - 1)
		return pos;

	if (!v) {
		dst[pos++] = '0';
		dst[pos] = '\0';
		return pos;
	}

	while (v && i < 20) {
		tmp[i++] = '0' + (v % 10);
		v /= 10;
	}

	while (i--) {
		if (pos >= max - 1)
			break;
		dst[pos++] = tmp[i];
	}

	dst[pos] = '\0';
	return pos;
}

static __always_inline int append_s64_dec(char *dst, int pos, int max, __s64 v)
{
	if (v < 0) {
		if (pos < max - 1)
			dst[pos++] = '-';
		v = -v;
	}

	return append_u64_dec(dst, pos, max, (__u64)v);
}

static __always_inline void emit_event(struct op_ctx *op, __s32 ret)
{
	struct iosnoop_event *e;
	__u64 uid_gid;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid & 0xffffffff;
	e->gid = uid_gid >> 32;
	e->type = op->type;
	e->ret = ret;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(e->fname, 0, sizeof(e->fname));
	__builtin_memset(e->args, 0, sizeof(e->args));
	__builtin_memcpy(e->fname, op->fname, sizeof(op->fname));
	__builtin_memcpy(e->args, op->args, sizeof(op->args));

	bpf_ringbuf_submit(e, 0);
}

static __always_inline void submit_or_drop(__u64 id, struct op_ctx *op)
{
	struct op_key key = {
		.id = id,
		.type = op->type,
	};

	if (!pass_mount_filter(op->dev))
		return;

	bpf_map_update_elem(&op_state, &key, op, BPF_ANY);
}

static __always_inline void submit_syscall_event(__u64 id, __u8 type,
							 const char *path)
{
	struct op_ctx op = {};
	__u32 dev = configured_mount_dev();

	op.type = type;
	op.dev = dev;
	op.args[0] = '\0';
	if (path)
		bpf_probe_read_user_str(op.fname, sizeof(op.fname), path);
	if (!pass_mount_filter(dev))
		return;
	emit_event(&op, 0);
}

static __always_inline void finish_event(__u64 id, __u32 type, __s32 ret)
{
	struct op_key key = {
		.id = id,
		.type = type,
	};
	struct op_ctx *op;

	op = bpf_map_lookup_elem(&op_state, &key);
	if (!op)
		return;

	emit_event(op, ret);
	bpf_map_delete_elem(&op_state, &key);
}

SEC("kprobe/__x64_sys_open")
int BPF_KPROBE(trace_sys_open_entry, const char *pathname, int flags, umode_t mode)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_OPEN, pathname);
	return 0;
}

SEC("kretprobe/__x64_sys_open")
int BPF_KRETPROBE(trace_sys_open_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_OPEN, (long)ret);
	return 0;
}

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(trace_sys_openat_entry, int dfd, const char *pathname, int flags,
		       umode_t mode)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_OPENAT, pathname);
	return 0;
}

SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(trace_sys_openat_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_OPENAT, (long)ret);
	return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(trace_sys_read_entry, int fd, char *buf, size_t count)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_READ, NULL);
	return 0;
}

SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(trace_sys_read_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_READ, (long)ret);
	return 0;
}

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(trace_sys_write_entry, int fd, const char *buf, size_t count)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_WRITE, NULL);
	return 0;
}

SEC("kretprobe/__x64_sys_write")
int BPF_KRETPROBE(trace_sys_write_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_WRITE, (long)ret);
	return 0;
}

SEC("kprobe/__x64_sys_mkdir")
int BPF_KPROBE(trace_sys_mkdir_entry, const char *pathname, umode_t mode)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_MKDIR, pathname);
	return 0;
}

SEC("kretprobe/__x64_sys_mkdir")
int BPF_KRETPROBE(trace_sys_mkdir_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_MKDIR, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_sys_enter_mkdir(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[0];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_MKDIR, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_sys_exit_mkdir(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_MKDIR, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_unlink")
int BPF_KPROBE(trace_sys_unlink_entry, const char *pathname)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_UNLINK, pathname);
	return 0;
}

SEC("kretprobe/__x64_sys_unlink")
int BPF_KRETPROBE(trace_sys_unlink_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_UNLINK, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_sys_enter_unlink(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[0];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_UNLINK, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_sys_exit_unlink(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_UNLINK, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_rename")
int BPF_KPROBE(trace_sys_rename_entry, const char *oldpath, const char *newpath)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_RENAME, newpath);
	return 0;
}

SEC("kretprobe/__x64_sys_rename")
int BPF_KRETPROBE(trace_sys_rename_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_RENAME, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_sys_enter_rename(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[1];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_RENAME, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_sys_exit_rename(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_RENAME, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_link")
int BPF_KPROBE(trace_sys_link_entry, const char *oldpath, const char *newpath)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_LINK, newpath);
	return 0;
}

SEC("kretprobe/__x64_sys_link")
int BPF_KRETPROBE(trace_sys_link_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_LINK, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_sys_enter_link(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[1];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_LINK, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_sys_exit_link(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_LINK, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_symlink")
int BPF_KPROBE(trace_sys_symlink_entry, const char *target, const char *linkpath)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_SYMLINK, linkpath);
	return 0;
}

SEC("kretprobe/__x64_sys_symlink")
int BPF_KRETPROBE(trace_sys_symlink_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_SYMLINK, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_sys_enter_symlink(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[1];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_SYMLINK, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_sys_exit_symlink(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_SYMLINK, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_readlink")
int BPF_KPROBE(trace_sys_readlink_entry, const char *pathname, char *buf,
		       size_t bufsiz)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_READLINK, pathname);
	return 0;
}

SEC("kretprobe/__x64_sys_readlink")
int BPF_KRETPROBE(trace_sys_readlink_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_READLINK, (long)ret);
	return 0;
}

SEC("kprobe/__x64_sys_truncate")
int BPF_KPROBE(trace_sys_truncate_entry, const char *path, long length)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_TRUNCATE, path);
	return 0;
}

SEC("kretprobe/__x64_sys_truncate")
int BPF_KRETPROBE(trace_sys_truncate_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_TRUNCATE, (long)ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_sys_enter_truncate(struct trace_event_raw_sys_enter *args)
{
	const char *path = (const char *)(unsigned long)args->args[0];
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_TRUNCATE, path);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int trace_sys_exit_truncate(struct trace_event_raw_sys_exit *args)
{
	finish_event(bpf_get_current_pid_tgid(), IO_TRUNCATE, (long)args->ret);
	return 0;
}

SEC("kprobe/__x64_sys_mmap")
int BPF_KPROBE(trace_sys_mmap_entry, unsigned long addr, unsigned long len,
		       unsigned long prot, unsigned long flags, unsigned long fd,
		       unsigned long pgoff)
{
	submit_syscall_event(bpf_get_current_pid_tgid(), IO_MMAP, NULL);
	return 0;
}

SEC("kretprobe/__x64_sys_mmap")
int BPF_KRETPROBE(trace_sys_mmap_exit, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_MMAP, (long)ret);
	return 0;
}

SEC("fentry/vfs_open")
int BPF_PROG(trace_vfs_open_enter, struct path *path, struct file *file)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int pos = 0;
	__u32 flags;

	op.type = IO_OPEN;
	op.dev = dev_from_path(path);
	read_path_name(path, op.fname, sizeof(op.fname));
	flags = file ? BPF_CORE_READ(file, f_flags) : 0;
	pos = append_lit(op.args, pos, sizeof(op.args), "flags=");
	append_u64_dec(op.args, pos, sizeof(op.args), flags);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_open")
int BPF_PROG(trace_vfs_open_exit, struct path *path, struct file *file, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_OPEN, ret);
	return 0;
}

SEC("fentry/vfs_read")
int BPF_PROG(trace_vfs_read_enter, struct file *file, char *buf, size_t count,
	     loff_t *pos)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;
	__s64 off = -1;

	if (pos)
		bpf_probe_read_kernel(&off, sizeof(off), pos);

	op.type = IO_READ;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "count=");
	p = append_u64_dec(op.args, p, sizeof(op.args), count);
	p = append_lit(op.args, p, sizeof(op.args), " pos=");
	append_s64_dec(op.args, p, sizeof(op.args), off);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_READ, ret);
	return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(trace_vfs_write_enter, struct file *file, const char *buf,
	     size_t count, loff_t *pos)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;
	__s64 off = -1;

	if (pos)
		bpf_probe_read_kernel(&off, sizeof(off), pos);

	op.type = IO_WRITE;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "count=");
	p = append_u64_dec(op.args, p, sizeof(op.args), count);
	p = append_lit(op.args, p, sizeof(op.args), " pos=");
	append_s64_dec(op.args, p, sizeof(op.args), off);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(trace_vfs_write_exit, struct file *file, const char *buf,
	     size_t count, loff_t *pos, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_WRITE, ret);
	return 0;
}

SEC("fentry/vfs_create")
int BPF_PROG(trace_vfs_create_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, bool want_excl)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_CREATE;
	op.dev = dev_from_inode(dir);
	read_dentry_name(dentry, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "mode=");
	p = append_u64_dec(op.args, p, sizeof(op.args), mode);
	p = append_lit(op.args, p, sizeof(op.args), " excl=");
	append_u64_dec(op.args, p, sizeof(op.args), want_excl ? 1 : 0);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_create")
int BPF_PROG(trace_vfs_create_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, bool want_excl, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_CREATE, ret);
	return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(trace_vfs_mkdir_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_MKDIR;
	op.dev = dev_from_inode(dir);
	read_dentry_name(dentry, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "mode=");
	append_u64_dec(op.args, p, sizeof(op.args), mode);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(trace_vfs_mkdir_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_MKDIR, ret);
	return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(trace_vfs_rmdir_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};

	op.type = IO_RMDIR;
	op.dev = dev_from_inode(dir);
	read_dentry_name(dentry, op.fname, sizeof(op.fname));
	op.args[0] = '\0';
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(trace_vfs_rmdir_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_RMDIR, ret);
	return 0;
}

SEC("fentry/vfs_symlink")
int BPF_PROG(trace_vfs_symlink_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *oldname)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	char target[64];
	int p = 0;

	op.type = IO_SYMLINK;
	op.dev = dev_from_inode(dir);
	read_dentry_name(dentry, op.fname, sizeof(op.fname));
	target[0] = '\0';
	if (oldname)
		bpf_probe_read_kernel_str(target, sizeof(target), oldname);
	p = append_lit(op.args, p, sizeof(op.args), "target=");
	append_lit(op.args, p, sizeof(op.args), target);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_symlink")
int BPF_PROG(trace_vfs_symlink_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *oldname, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_SYMLINK, ret);
	return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(trace_vfs_rename_enter, struct renamedata *rd)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	struct dentry *new_parent;
	struct dentry *new_dentry;
	struct inode *new_dir;

	if (!rd)
		return 0;

	new_dentry = BPF_CORE_READ(rd, new_dentry);

	op.type = IO_RENAME;
	if (bpf_core_field_exists(rd->new_parent)) {
		new_parent = BPF_CORE_READ(rd, new_parent);
		op.dev = dev_from_dentry(new_parent);
	} else {
		new_dir = BPF_CORE_READ((struct renamedata___legacy *)rd, new_dir);
		op.dev = dev_from_inode(new_dir);
	}
	read_dentry_name(new_dentry, op.fname, sizeof(op.fname));
	op.args[0] = '\0';
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(trace_vfs_rename_exit, struct renamedata *rd, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_RENAME, ret);
	return 0;
}

SEC("fentry/vfs_getattr")
int BPF_PROG(trace_vfs_getattr_enter, const struct path *path, struct kstat *stat,
	     u32 request_mask, unsigned int query_flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;
	struct path pth;

	if (!path)
		return 0;

	bpf_probe_read_kernel(&pth, sizeof(pth), path);
	op.type = IO_STAT;
	op.dev = dev_from_path(&pth);
	read_path_name(&pth, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "mask=");
	p = append_u64_dec(op.args, p, sizeof(op.args), request_mask);
	p = append_lit(op.args, p, sizeof(op.args), " qflags=");
	append_u64_dec(op.args, p, sizeof(op.args), query_flags);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_getattr")
int BPF_PROG(trace_vfs_getattr_exit, const struct path *path, struct kstat *stat,
	     u32 request_mask, unsigned int query_flags, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_STAT, ret);
	return 0;
}

SEC("fentry/vfs_truncate")
int BPF_PROG(trace_vfs_truncate_enter, const struct path *path, loff_t length)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;
	struct path pth;

	if (!path)
		return 0;

	bpf_probe_read_kernel(&pth, sizeof(pth), path);
	op.type = IO_TRUNCATE;
	op.dev = dev_from_path(&pth);
	read_path_name(&pth, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "length=");
	append_s64_dec(op.args, p, sizeof(op.args), length);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_truncate")
int BPF_PROG(trace_vfs_truncate_exit, const struct path *path, loff_t length,
	     int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_TRUNCATE, ret);
	return 0;
}

SEC("fentry/vfs_fchmod")
int BPF_PROG(trace_vfs_fchmod_enter, struct file *file, umode_t mode)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_FCHMOD;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "mode=");
	append_u64_dec(op.args, p, sizeof(op.args), mode);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_fchmod")
int BPF_PROG(trace_vfs_fchmod_exit, struct file *file, umode_t mode, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_FCHMOD, ret);
	return 0;
}

SEC("fentry/vfs_readlink")
int BPF_PROG(trace_vfs_readlink_enter, struct dentry *dentry, char *buffer,
	     int buflen)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_READLINK;
	op.dev = dev_from_dentry(dentry);
	read_dentry_name(dentry, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "buflen=");
	append_u64_dec(op.args, p, sizeof(op.args), buflen);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_readlink")
int BPF_PROG(trace_vfs_readlink_exit, struct dentry *dentry, char *buffer,
	     int buflen, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_READLINK, ret);
	return 0;
}

SEC("fentry/vfs_readv")
int BPF_PROG(trace_vfs_readv_enter, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_READV;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "vlen=");
	p = append_u64_dec(op.args, p, sizeof(op.args), vlen);
	p = append_lit(op.args, p, sizeof(op.args), " flags=");
	append_u64_dec(op.args, p, sizeof(op.args), flags);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_readv")
int BPF_PROG(trace_vfs_readv_exit, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_READV, ret);
	return 0;
}

SEC("fentry/vfs_writev")
int BPF_PROG(trace_vfs_writev_enter, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_WRITEV;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "vlen=");
	p = append_u64_dec(op.args, p, sizeof(op.args), vlen);
	p = append_lit(op.args, p, sizeof(op.args), " flags=");
	append_u64_dec(op.args, p, sizeof(op.args), flags);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_writev")
int BPF_PROG(trace_vfs_writev_exit, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_WRITEV, ret);
	return 0;
}

/* Fallback probes for kernels where some fentry/fexit signatures fail verifier checks. */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(trace_vfs_unlink_kp, struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *dentry, struct inode **delegated_inode)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx opv = {};

	opv.type = IO_UNLINK;
	opv.dev = dev_from_inode(dir);
	read_dentry_name(dentry, opv.fname, sizeof(opv.fname));
	opv.args[0] = '\0';
	submit_or_drop(id, &opv);
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(trace_vfs_unlink_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_UNLINK, (__s32)ret);
	return 0;
}

SEC("kprobe/vfs_link")
int BPF_KPROBE(trace_vfs_link_kp, struct dentry *old_dentry,
	       struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *new_dentry, struct inode **delegated_inode)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx opv = {};
	char old_name[64];
	int p = 0;

	opv.type = IO_LINK;
	opv.dev = dev_from_inode(dir);
	read_dentry_name(new_dentry, opv.fname, sizeof(opv.fname));
	read_dentry_name(old_dentry, old_name, sizeof(old_name));
	p = append_lit(opv.args, p, sizeof(opv.args), "old=");
	append_lit(opv.args, p, sizeof(opv.args), old_name);
	submit_or_drop(id, &opv);
	return 0;
}

SEC("kretprobe/vfs_link")
int BPF_KRETPROBE(trace_vfs_link_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_LINK, (__s32)ret);
	return 0;
}

SEC("kprobe/vfs_fallocate")
int BPF_KPROBE(trace_vfs_fallocate_kp, struct file *file, int mode,
	       loff_t offset, loff_t len)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_FALLOCATE;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "offset=");
	p = append_s64_dec(op.args, p, sizeof(op.args), offset);
	p = append_lit(op.args, p, sizeof(op.args), " len=");
	append_s64_dec(op.args, p, sizeof(op.args), len);
	submit_or_drop(id, &op);
	return 0;
}

SEC("kretprobe/vfs_fallocate")
int BPF_KRETPROBE(trace_vfs_fallocate_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_FALLOCATE, (__s32)ret);
	return 0;
}

SEC("fentry/iterate_dir")
int BPF_PROG(trace_iterate_dir_enter, struct file *file, struct dir_context *dctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};

	op.type = IO_GETDENTS;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	op.args[0] = '\0';
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/iterate_dir")
int BPF_PROG(trace_iterate_dir_exit, struct file *file, struct dir_context *dctx,
	     int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_GETDENTS, ret);
	return 0;
}

SEC("kprobe/do_mmap")
int BPF_KPROBE(trace_do_mmap_kp, struct file *file, unsigned long addr,
	       unsigned long len, unsigned long prot, unsigned long flags)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	if (!file)
		return 0;

	op.type = IO_MMAP;
	op.dev = dev_from_file(file);
	read_file_name(file, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "len=");
	p = append_u64_dec(op.args, p, sizeof(op.args), len);
	p = append_lit(op.args, p, sizeof(op.args), " prot=");
	append_u64_dec(op.args, p, sizeof(op.args), prot);
	submit_or_drop(id, &op);
	return 0;
}

SEC("kretprobe/do_mmap")
int BPF_KRETPROBE(trace_do_mmap_krp, unsigned long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_key opk = {
		.id = id,
		.type = IO_MMAP,
	};
	struct op_ctx *op;
	__u32 pid = (__u32)(id >> 32);
	__u64 vma_key;
	__u32 dev;

	op = bpf_map_lookup_elem(&op_state, &opk);
	if (op && (long)ret > 0) {
		dev = op->dev;
		vma_key = ((__u64)pid << 32) | (ret >> 12);
		bpf_map_update_elem(&vma_dev_map, &vma_key, &dev, BPF_ANY);
	}
	finish_event(id, IO_MMAP, (long)ret > 0 ? 0 : (__s32)(long)ret);
	return 0;
}

SEC("kprobe/vm_munmap")
int BPF_KPROBE(trace_vm_munmap_kp, unsigned long start, size_t len)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(id >> 32);
	__u64 key = ((__u64)pid << 32) | (start >> 12);
	struct op_ctx op = {};
	__u32 *devp;
	int p = 0;

	devp = bpf_map_lookup_elem(&vma_dev_map, &key);
	op.dev = devp ? *devp : 0;
	bpf_map_delete_elem(&vma_dev_map, &key);

	op.type = IO_MUNMAP;
	p = append_lit(op.args, p, sizeof(op.args), "len=");
	append_u64_dec(op.args, p, sizeof(op.args), (unsigned long)len);
	op.fname[0] = '\0';
	submit_or_drop(id, &op);
	return 0;
}

SEC("kretprobe/vm_munmap")
int BPF_KRETPROBE(trace_vm_munmap_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_MUNMAP, (__s32)ret);
	return 0;
}

SEC("fentry/vfs_lock_file")
int BPF_PROG(trace_vfs_lock_file_enter, struct file *filp, unsigned int cmd,
	     struct file_lock *fl, struct file_lock *conf)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};
	int p = 0;

	op.type = IO_LOCK_FCNTL;
	op.dev = dev_from_file(filp);
	read_file_name(filp, op.fname, sizeof(op.fname));
	p = append_lit(op.args, p, sizeof(op.args), "cmd=");
	append_u64_dec(op.args, p, sizeof(op.args), cmd);
	submit_or_drop(id, &op);
	return 0;
}

SEC("fexit/vfs_lock_file")
int BPF_PROG(trace_vfs_lock_file_exit, struct file *filp, unsigned int cmd,
	     struct file_lock *fl, struct file_lock *conf, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), IO_LOCK_FCNTL, ret);
	return 0;
}

#define DEFINE_KRETPROBE_FALLBACK(target, name, type) \
	SEC("kretprobe/" #target) \
	int BPF_KRETPROBE(name, long ret) \
	{ \
		finish_event(bpf_get_current_pid_tgid(), type, (__s32)ret); \
		return 0; \
	}

SEC("kprobe/vfs_open")
int BPF_KPROBE(trace_vfs_open_kprobe_fallback, struct path *path,
	       struct file *file)
{
	return ____trace_vfs_open_enter((unsigned long long *)ctx, path, file);
}
DEFINE_KRETPROBE_FALLBACK(vfs_open, trace_vfs_open_kretprobe_fallback,
			  IO_OPEN);

SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_vfs_read_kprobe_fallback, struct file *file, char *buf,
	       size_t count, loff_t *pos)
{
	return ____trace_vfs_read_enter((unsigned long long *)ctx, file, buf,
				      count, pos);
}
DEFINE_KRETPROBE_FALLBACK(vfs_read, trace_vfs_read_kretprobe_fallback,
			  IO_READ);

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_kprobe_fallback, struct file *file,
	       const char *buf, size_t count, loff_t *pos)
{
	return ____trace_vfs_write_enter((unsigned long long *)ctx, file, buf,
				       count, pos);
}
DEFINE_KRETPROBE_FALLBACK(vfs_write, trace_vfs_write_kretprobe_fallback,
			  IO_WRITE);

SEC("kprobe/vfs_create")
int BPF_KPROBE(trace_vfs_create_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, umode_t mode,
	       bool want_excl)
{
	return ____trace_vfs_create_enter((unsigned long long *)ctx, idmap, dir,
					dentry, mode, want_excl);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(trace_vfs_create_legacy_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return ____trace_vfs_create_enter((unsigned long long *)ctx, idmap, dir,
					dentry, mode, false);
}
DEFINE_KRETPROBE_FALLBACK(vfs_create, trace_vfs_create_kretprobe_fallback,
			  IO_CREATE);

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(trace_vfs_mkdir_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return ____trace_vfs_mkdir_enter((unsigned long long *)ctx, idmap, dir,
				       dentry, mode);
}
DEFINE_KRETPROBE_FALLBACK(vfs_mkdir, trace_vfs_mkdir_kretprobe_fallback,
			  IO_MKDIR);

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(trace_vfs_rmdir_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry)
{
	return ____trace_vfs_rmdir_enter((unsigned long long *)ctx, idmap, dir,
				       dentry);
}
DEFINE_KRETPROBE_FALLBACK(vfs_rmdir, trace_vfs_rmdir_kretprobe_fallback,
			  IO_RMDIR);

SEC("kprobe/vfs_symlink")
int BPF_KPROBE(trace_vfs_symlink_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, const char *oldname)
{
	return ____trace_vfs_symlink_enter((unsigned long long *)ctx, idmap, dir,
					 dentry, oldname);
}
DEFINE_KRETPROBE_FALLBACK(vfs_symlink, trace_vfs_symlink_kretprobe_fallback,
			  IO_SYMLINK);

SEC("kprobe/vfs_rename")
int BPF_KPROBE(trace_vfs_rename_kprobe_fallback, struct renamedata *rd)
{
	return ____trace_vfs_rename_enter((unsigned long long *)ctx, rd);
}
DEFINE_KRETPROBE_FALLBACK(vfs_rename, trace_vfs_rename_kretprobe_fallback,
			  IO_RENAME);

SEC("kprobe/vfs_rename")
int BPF_KPROBE(trace_vfs_rename_legacy_kprobe_fallback,
	       struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct op_ctx op = {};

	op.type = IO_RENAME;
	op.dev = dev_from_inode(new_dir);
	read_dentry_name(new_dentry, op.fname, sizeof(op.fname));
	op.args[0] = '\0';
	submit_or_drop(id, &op);
	return 0;
}
DEFINE_KRETPROBE_FALLBACK(vfs_rename,
			  trace_vfs_rename_legacy_kretprobe_fallback,
			  IO_RENAME);

SEC("kprobe/vfs_getattr")
int BPF_KPROBE(trace_vfs_getattr_kprobe_fallback, const struct path *path,
	       struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	return ____trace_vfs_getattr_enter((unsigned long long *)ctx, path, stat,
					 request_mask, query_flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_getattr, trace_vfs_getattr_kretprobe_fallback,
			  IO_STAT);

SEC("kprobe/vfs_truncate")
int BPF_KPROBE(trace_vfs_truncate_kprobe_fallback, const struct path *path,
	       loff_t length)
{
	return ____trace_vfs_truncate_enter((unsigned long long *)ctx, path,
					  length);
}
DEFINE_KRETPROBE_FALLBACK(vfs_truncate,
			  trace_vfs_truncate_kretprobe_fallback, IO_TRUNCATE);

SEC("kprobe/vfs_fchmod")
int BPF_KPROBE(trace_vfs_fchmod_kprobe_fallback, struct file *file,
	       umode_t mode)
{
	return ____trace_vfs_fchmod_enter((unsigned long long *)ctx, file, mode);
}
DEFINE_KRETPROBE_FALLBACK(vfs_fchmod, trace_vfs_fchmod_kretprobe_fallback,
			  IO_FCHMOD);

SEC("kprobe/vfs_readlink")
int BPF_KPROBE(trace_vfs_readlink_kprobe_fallback, struct dentry *dentry,
	       char *buffer, int buflen)
{
	return ____trace_vfs_readlink_enter((unsigned long long *)ctx, dentry,
					 buffer, buflen);
}
DEFINE_KRETPROBE_FALLBACK(vfs_readlink,
			  trace_vfs_readlink_kretprobe_fallback, IO_READLINK);

SEC("kprobe/vfs_readv")
int BPF_KPROBE(trace_vfs_readv_kprobe_fallback, struct file *file,
	       const struct iovec *vec, unsigned long vlen, loff_t *pos,
	       unsigned int flags)
{
	return ____trace_vfs_readv_enter((unsigned long long *)ctx, file, vec,
				       vlen, pos, flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_readv, trace_vfs_readv_kretprobe_fallback,
			  IO_READV);

SEC("kprobe/vfs_writev")
int BPF_KPROBE(trace_vfs_writev_kprobe_fallback, struct file *file,
	       const struct iovec *vec, unsigned long vlen, loff_t *pos,
	       unsigned int flags)
{
	return ____trace_vfs_writev_enter((unsigned long long *)ctx, file, vec,
					vlen, pos, flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_writev, trace_vfs_writev_kretprobe_fallback,
			  IO_WRITEV);

SEC("kprobe/iterate_dir")
int BPF_KPROBE(trace_iterate_dir_kprobe_fallback, struct file *file,
	       struct dir_context *dctx)
{
	return ____trace_iterate_dir_enter((unsigned long long *)ctx, file, dctx);
}
DEFINE_KRETPROBE_FALLBACK(iterate_dir,
			  trace_iterate_dir_kretprobe_fallback, IO_GETDENTS);

SEC("kprobe/vfs_lock_file")
int BPF_KPROBE(trace_vfs_lock_file_kprobe_fallback, struct file *filp,
	       unsigned int cmd, struct file_lock *fl, struct file_lock *conf)
{
	return ____trace_vfs_lock_file_enter((unsigned long long *)ctx, filp, cmd,
					   fl, conf);
}
DEFINE_KRETPROBE_FALLBACK(vfs_lock_file,
			  trace_vfs_lock_file_kretprobe_fallback, IO_LOCK_FCNTL);

char LICENSE[] SEC("license") = "GPL";
