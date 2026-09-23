#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct renamedata___legacy {
	struct inode *new_dir;
	struct dentry *new_dentry;
} __attribute__((preserve_access_index));

#define RINGBUF_SIZE (256 * 1024)

/* Operation types */
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
#define SC_MMAP		45
#define SC_MUNMAP	47
#define SC_CREATE	48
#define SC_FALLOCATE	49
#define SC_GETDENTS	50
#define SC_LOCK_FCNTL	51
#define SC_LOCK_FLOCK	52

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

struct mount_filter_cfg {
	__u32 enabled;
	__u32 dev_major;
	__u32 dev_minor;
};

struct start_t {
	__u64 ts;
	__u8 type;
	__u8 __pad1;
	__u16 __pad2;
	__u32 dev;
	char fname[96];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct start_t);
} op_start SEC(".maps");

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

/* Key 0: latency threshold in microseconds. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} threshold_config SEC(".maps");

/* Key 0: mount filter configuration (enabled + target s_dev). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mount_filter_cfg);
} mount_filter_cfg SEC(".maps");

static __always_inline bool pass_mount_filter(__u32 dev)
{
	__u32 key = 0;
	struct mount_filter_cfg *cfg;
	__u32 dev_major;
	__u32 dev_minor;

	cfg = bpf_map_lookup_elem(&mount_filter_cfg, &key);
	if (!cfg || !cfg->enabled)
		return true;

	dev_major = dev >> 20;
	dev_minor = dev & ((1U << 20) - 1);

	return cfg->dev_major == dev_major && cfg->dev_minor == dev_minor;
}

static __always_inline __u32 dev_from_path(struct path *path)
{
	struct super_block *sb;

	if (!path)
		return 0;

	sb = BPF_CORE_READ(path, dentry, d_sb);
	if (!sb)
		return 0;

	return BPF_CORE_READ(sb, s_dev);
}

static __always_inline __u32 dev_from_file(struct file *file)
{
	struct super_block *sb;
	struct inode *inode;

	if (!file)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb)
		return 0;

	return BPF_CORE_READ(sb, s_dev);
}

static __always_inline __u32 dev_from_dentry(struct dentry *dentry)
{
	struct super_block *sb;

	if (!dentry)
		return 0;

	sb = BPF_CORE_READ(dentry, d_sb);
	if (!sb)
		return 0;

	return BPF_CORE_READ(sb, s_dev);
}

static __always_inline __u32 dev_from_inode(struct inode *inode)
{
	struct super_block *sb;

	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb)
		return 0;

	return BPF_CORE_READ(sb, s_dev);
}

static __always_inline void read_dentry_name(struct dentry *dentry, char *dst,
				      int dst_sz)
{
	const unsigned char *name;

	if (!dentry || dst_sz <= 0) {
		dst[0] = '\0';
		return;
	}

	name = BPF_CORE_READ(dentry, d_name.name);
	if (!name || bpf_probe_read_kernel_str(dst, dst_sz, name) < 0)
		dst[0] = '\0';
}

static __always_inline void read_path_name(struct path *path, char *dst, int dst_sz)
{
	if (!path) {
		dst[0] = '\0';
		return;
	}

	read_dentry_name(BPF_CORE_READ(path, dentry), dst, dst_sz);
}

static __always_inline void read_file_name(struct file *file, char *dst, int dst_sz)
{
	struct dentry *dentry;

	if (!file) {
		dst[0] = '\0';
		return;
	}

	dentry = BPF_CORE_READ(file, f_path.dentry);
	read_dentry_name(dentry, dst, dst_sz);
}

static __always_inline void emit_event(struct start_t *st, __u64 delta_ns, __s32 ret)
{
	struct ioslower_event *e;
	__u64 *threshold_us;
	__u64 delta_us;
	__u32 zero = 0;
	__u64 uid_gid;

	threshold_us = bpf_map_lookup_elem(&threshold_config, &zero);
	if (!threshold_us)
		return;

	delta_us = delta_ns / 1000;
	if (delta_us < *threshold_us)
		return;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid & 0xffffffff;
	e->gid = uid_gid >> 32;
	e->type = st->type;
	e->ret = ret;
	e->delta_us = delta_us;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(e->fname, 0, sizeof(e->fname));
	__builtin_memcpy(e->fname, st->fname, sizeof(st->fname));

	bpf_ringbuf_submit(e, 0);
}

static __always_inline void start_or_drop(__u64 id, struct start_t *st)
{
	if (!pass_mount_filter(st->dev))
		return;

	bpf_map_update_elem(&op_start, &id, st, BPF_ANY);
}

static __always_inline void finish_event(__u64 id, __s32 ret)
{
	struct start_t *st;
	__u64 delta;

	st = bpf_map_lookup_elem(&op_start, &id);
	if (!st)
		return;

	delta = bpf_ktime_get_ns() - st->ts;
	emit_event(st, delta, ret);
	bpf_map_delete_elem(&op_start, &id);
}

SEC("fentry/vfs_open")
int BPF_PROG(trace_vfs_open_enter, struct path *path, struct file *file)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_OPEN;
	st.dev = dev_from_path(path);
	read_path_name(path, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_open")
int BPF_PROG(trace_vfs_open_exit, struct path *path, struct file *file, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_read")
int BPF_PROG(trace_vfs_read_enter, struct file *file, char *buf, size_t count,
	     loff_t *pos)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_READ;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, char *buf, size_t count,
	     loff_t *pos, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(trace_vfs_write_enter, struct file *file, const char *buf,
	     size_t count, loff_t *pos)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_WRITE;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(trace_vfs_write_exit, struct file *file, const char *buf,
	     size_t count, loff_t *pos, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_create")
int BPF_PROG(trace_vfs_create_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, bool want_excl)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_CREATE;
	st.dev = dev_from_inode(dir);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_create")
int BPF_PROG(trace_vfs_create_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, bool want_excl, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_mkdir")
int BPF_PROG(trace_vfs_mkdir_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_MKDIR;
	st.dev = dev_from_inode(dir);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_mkdir")
int BPF_PROG(trace_vfs_mkdir_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, umode_t mode, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_rmdir")
int BPF_PROG(trace_vfs_rmdir_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_RMDIR;
	st.dev = dev_from_inode(dir);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(trace_vfs_rmdir_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_symlink")
int BPF_PROG(trace_vfs_symlink_enter, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *oldname)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_SYMLINK;
	st.dev = dev_from_inode(dir);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_symlink")
int BPF_PROG(trace_vfs_symlink_exit, struct mnt_idmap *idmap, struct inode *dir,
	     struct dentry *dentry, const char *oldname, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(trace_vfs_rename_enter, struct renamedata *rd)
{
	struct start_t st = {};
	struct dentry *new_parent;
	struct dentry *new_dentry;
	struct inode *new_dir;

	if (!rd)
		return 0;

	new_dentry = BPF_CORE_READ(rd, new_dentry);

	st.ts = bpf_ktime_get_ns();
	st.type = SC_RENAME;
	if (bpf_core_field_exists(rd->new_parent)) {
		new_parent = BPF_CORE_READ(rd, new_parent);
		st.dev = dev_from_dentry(new_parent);
	} else {
		new_dir = BPF_CORE_READ((struct renamedata___legacy *)rd, new_dir);
		st.dev = dev_from_inode(new_dir);
	}
	read_dentry_name(new_dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(trace_vfs_rename_exit, struct renamedata *rd, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_getattr")
int BPF_PROG(trace_vfs_getattr_enter, const struct path *path, struct kstat *stat,
	     u32 request_mask, unsigned int query_flags)
{
	struct start_t st = {};
	struct path pth;

	if (!path)
		return 0;

	bpf_probe_read_kernel(&pth, sizeof(pth), path);
	st.ts = bpf_ktime_get_ns();
	st.type = SC_STAT;
	st.dev = dev_from_path(&pth);
	read_path_name(&pth, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_getattr")
int BPF_PROG(trace_vfs_getattr_exit, const struct path *path, struct kstat *stat,
	     u32 request_mask, unsigned int query_flags, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_truncate")
int BPF_PROG(trace_vfs_truncate_enter, const struct path *path, loff_t length)
{
	struct start_t st = {};
	struct path pth;

	if (!path)
		return 0;

	bpf_probe_read_kernel(&pth, sizeof(pth), path);
	st.ts = bpf_ktime_get_ns();
	st.type = SC_TRUNCATE;
	st.dev = dev_from_path(&pth);
	read_path_name(&pth, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_truncate")
int BPF_PROG(trace_vfs_truncate_exit, const struct path *path, loff_t length,
	     int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_fchmod")
int BPF_PROG(trace_vfs_fchmod_enter, struct file *file, umode_t mode)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_FCHMOD;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_fchmod")
int BPF_PROG(trace_vfs_fchmod_exit, struct file *file, umode_t mode, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_readlink")
int BPF_PROG(trace_vfs_readlink_enter, struct dentry *dentry, char *buffer,
	     int buflen)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_READLINK;
	st.dev = dev_from_dentry(dentry);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_readlink")
int BPF_PROG(trace_vfs_readlink_exit, struct dentry *dentry, char *buffer,
	     int buflen, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_readv")
int BPF_PROG(trace_vfs_readv_enter, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_READV;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_readv")
int BPF_PROG(trace_vfs_readv_exit, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("fentry/vfs_writev")
int BPF_PROG(trace_vfs_writev_enter, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_WRITEV;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_writev")
int BPF_PROG(trace_vfs_writev_exit, struct file *file, const struct iovec *vec,
	     unsigned long vlen, loff_t *pos, unsigned int flags, ssize_t ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

/* Fallback probes for kernels where some fentry/fexit signatures fail verifier checks. */
SEC("kprobe/vfs_unlink")
int BPF_KPROBE(trace_vfs_unlink_kp, struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *dentry, struct inode **delegated_inode)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_UNLINK;
	st.dev = dev_from_inode(dir);
	read_dentry_name(dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(trace_vfs_unlink_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), (__s32)ret);
	return 0;
}

SEC("kprobe/vfs_link")
int BPF_KPROBE(trace_vfs_link_kp, struct dentry *old_dentry,
	       struct mnt_idmap *idmap, struct inode *dir,
	       struct dentry *new_dentry, struct inode **delegated_inode)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_LINK;
	st.dev = dev_from_inode(dir);
	read_dentry_name(new_dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("kretprobe/vfs_link")
int BPF_KRETPROBE(trace_vfs_link_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), (__s32)ret);
	return 0;
}

SEC("kprobe/vfs_fallocate")
int BPF_KPROBE(trace_vfs_fallocate_kp, struct file *file, int mode,
	       loff_t offset, loff_t len)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_FALLOCATE;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("kretprobe/vfs_fallocate")
int BPF_KRETPROBE(trace_vfs_fallocate_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), (__s32)ret);
	return 0;
}

SEC("fentry/iterate_dir")
int BPF_PROG(trace_iterate_dir_enter, struct file *file, struct dir_context *dctx)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_GETDENTS;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/iterate_dir")
int BPF_PROG(trace_iterate_dir_exit, struct file *file, struct dir_context *dctx,
	     int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

SEC("kprobe/do_mmap")
int BPF_KPROBE(trace_do_mmap_kp, struct file *file, unsigned long addr,
	       unsigned long len, unsigned long prot, unsigned long flags)
{
	struct start_t st = {};

	if (!file)
		return 0;

	st.ts = bpf_ktime_get_ns();
	st.type = SC_MMAP;
	st.dev = dev_from_file(file);
	read_file_name(file, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("kretprobe/do_mmap")
int BPF_KRETPROBE(trace_do_mmap_krp, unsigned long ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct start_t *st;
	__u32 pid = (__u32)(id >> 32);
	__u64 key;
	__u32 dev;

	st = bpf_map_lookup_elem(&op_start, &id);
	if (st && (long)ret > 0) {
		dev = st->dev;
		key = ((__u64)pid << 32) | (ret >> 12);
		bpf_map_update_elem(&vma_dev_map, &key, &dev, BPF_ANY);
	}
	finish_event(id, (long)ret > 0 ? 0 : (__s32)(long)ret);
	return 0;
}

SEC("kprobe/vm_munmap")
int BPF_KPROBE(trace_vm_munmap_kp, unsigned long start, size_t len)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(id >> 32);
	__u64 key = ((__u64)pid << 32) | (start >> 12);
	struct start_t st = {};
	__u32 *devp;

	devp = bpf_map_lookup_elem(&vma_dev_map, &key);
	st.dev = devp ? *devp : 0;
	bpf_map_delete_elem(&vma_dev_map, &key);

	st.ts = bpf_ktime_get_ns();
	st.type = SC_MUNMAP;
	st.fname[0] = '\0';
	start_or_drop(id, &st);
	return 0;
}

SEC("kretprobe/vm_munmap")
int BPF_KRETPROBE(trace_vm_munmap_krp, long ret)
{
	finish_event(bpf_get_current_pid_tgid(), (__s32)ret);
	return 0;
}

SEC("fentry/vfs_lock_file")
int BPF_PROG(trace_vfs_lock_file_enter, struct file *filp, unsigned int cmd,
	     struct file_lock *fl, struct file_lock *conf)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_LOCK_FCNTL;
	st.dev = dev_from_file(filp);
	read_file_name(filp, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}

SEC("fexit/vfs_lock_file")
int BPF_PROG(trace_vfs_lock_file_exit, struct file *filp, unsigned int cmd,
	     struct file_lock *fl, struct file_lock *conf, int ret)
{
	finish_event(bpf_get_current_pid_tgid(), ret);
	return 0;
}

#define DEFINE_KRETPROBE_FALLBACK(target, name) \
	SEC("kretprobe/" #target) \
	int BPF_KRETPROBE(name, long ret) \
	{ \
		finish_event(bpf_get_current_pid_tgid(), (__s32)ret); \
		return 0; \
	}

SEC("kprobe/vfs_open")
int BPF_KPROBE(trace_vfs_open_kprobe_fallback, struct path *path,
	       struct file *file)
{
	return ____trace_vfs_open_enter((unsigned long long *)ctx, path, file);
}
DEFINE_KRETPROBE_FALLBACK(vfs_open, trace_vfs_open_kretprobe_fallback);

SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_vfs_read_kprobe_fallback, struct file *file, char *buf,
	       size_t count, loff_t *pos)
{
	return ____trace_vfs_read_enter((unsigned long long *)ctx, file, buf,
				      count, pos);
}
DEFINE_KRETPROBE_FALLBACK(vfs_read, trace_vfs_read_kretprobe_fallback);

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_kprobe_fallback, struct file *file,
	       const char *buf, size_t count, loff_t *pos)
{
	return ____trace_vfs_write_enter((unsigned long long *)ctx, file, buf,
				       count, pos);
}
DEFINE_KRETPROBE_FALLBACK(vfs_write, trace_vfs_write_kretprobe_fallback);

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
DEFINE_KRETPROBE_FALLBACK(vfs_create, trace_vfs_create_kretprobe_fallback);

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(trace_vfs_mkdir_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return ____trace_vfs_mkdir_enter((unsigned long long *)ctx, idmap, dir,
				       dentry, mode);
}
DEFINE_KRETPROBE_FALLBACK(vfs_mkdir, trace_vfs_mkdir_kretprobe_fallback);

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(trace_vfs_rmdir_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry)
{
	return ____trace_vfs_rmdir_enter((unsigned long long *)ctx, idmap, dir,
				       dentry);
}
DEFINE_KRETPROBE_FALLBACK(vfs_rmdir, trace_vfs_rmdir_kretprobe_fallback);

SEC("kprobe/vfs_symlink")
int BPF_KPROBE(trace_vfs_symlink_kprobe_fallback, struct mnt_idmap *idmap,
	       struct inode *dir, struct dentry *dentry, const char *oldname)
{
	return ____trace_vfs_symlink_enter((unsigned long long *)ctx, idmap, dir,
					 dentry, oldname);
}
DEFINE_KRETPROBE_FALLBACK(vfs_symlink, trace_vfs_symlink_kretprobe_fallback);

SEC("kprobe/vfs_rename")
int BPF_KPROBE(trace_vfs_rename_kprobe_fallback, struct renamedata *rd)
{
	return ____trace_vfs_rename_enter((unsigned long long *)ctx, rd);
}
DEFINE_KRETPROBE_FALLBACK(vfs_rename, trace_vfs_rename_kretprobe_fallback);

SEC("kprobe/vfs_rename")
int BPF_KPROBE(trace_vfs_rename_legacy_kprobe_fallback,
	       struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	struct start_t st = {};

	st.ts = bpf_ktime_get_ns();
	st.type = SC_RENAME;
	st.dev = dev_from_inode(new_dir);
	read_dentry_name(new_dentry, st.fname, sizeof(st.fname));
	start_or_drop(bpf_get_current_pid_tgid(), &st);
	return 0;
}
DEFINE_KRETPROBE_FALLBACK(vfs_rename,
			  trace_vfs_rename_legacy_kretprobe_fallback);

SEC("kprobe/vfs_getattr")
int BPF_KPROBE(trace_vfs_getattr_kprobe_fallback, const struct path *path,
	       struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	return ____trace_vfs_getattr_enter((unsigned long long *)ctx, path, stat,
					 request_mask, query_flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_getattr, trace_vfs_getattr_kretprobe_fallback);

SEC("kprobe/vfs_truncate")
int BPF_KPROBE(trace_vfs_truncate_kprobe_fallback, const struct path *path,
	       loff_t length)
{
	return ____trace_vfs_truncate_enter((unsigned long long *)ctx, path,
					  length);
}
DEFINE_KRETPROBE_FALLBACK(vfs_truncate, trace_vfs_truncate_kretprobe_fallback);

SEC("kprobe/vfs_fchmod")
int BPF_KPROBE(trace_vfs_fchmod_kprobe_fallback, struct file *file,
	       umode_t mode)
{
	return ____trace_vfs_fchmod_enter((unsigned long long *)ctx, file, mode);
}
DEFINE_KRETPROBE_FALLBACK(vfs_fchmod, trace_vfs_fchmod_kretprobe_fallback);

SEC("kprobe/vfs_readlink")
int BPF_KPROBE(trace_vfs_readlink_kprobe_fallback, struct dentry *dentry,
	       char *buffer, int buflen)
{
	return ____trace_vfs_readlink_enter((unsigned long long *)ctx, dentry,
					 buffer, buflen);
}
DEFINE_KRETPROBE_FALLBACK(vfs_readlink, trace_vfs_readlink_kretprobe_fallback);

SEC("kprobe/vfs_readv")
int BPF_KPROBE(trace_vfs_readv_kprobe_fallback, struct file *file,
	       const struct iovec *vec, unsigned long vlen, loff_t *pos,
	       unsigned int flags)
{
	return ____trace_vfs_readv_enter((unsigned long long *)ctx, file, vec,
				       vlen, pos, flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_readv, trace_vfs_readv_kretprobe_fallback);

SEC("kprobe/vfs_writev")
int BPF_KPROBE(trace_vfs_writev_kprobe_fallback, struct file *file,
	       const struct iovec *vec, unsigned long vlen, loff_t *pos,
	       unsigned int flags)
{
	return ____trace_vfs_writev_enter((unsigned long long *)ctx, file, vec,
					vlen, pos, flags);
}
DEFINE_KRETPROBE_FALLBACK(vfs_writev, trace_vfs_writev_kretprobe_fallback);

SEC("kprobe/iterate_dir")
int BPF_KPROBE(trace_iterate_dir_kprobe_fallback, struct file *file,
	       struct dir_context *dctx)
{
	return ____trace_iterate_dir_enter((unsigned long long *)ctx, file, dctx);
}
DEFINE_KRETPROBE_FALLBACK(iterate_dir, trace_iterate_dir_kretprobe_fallback);

SEC("kprobe/vfs_lock_file")
int BPF_KPROBE(trace_vfs_lock_file_kprobe_fallback, struct file *filp,
	       unsigned int cmd, struct file_lock *fl, struct file_lock *conf)
{
	return ____trace_vfs_lock_file_enter((unsigned long long *)ctx, filp, cmd,
					   fl, conf);
}
DEFINE_KRETPROBE_FALLBACK(vfs_lock_file,
			  trace_vfs_lock_file_kretprobe_fallback);

char LICENSE[] SEC("license") = "GPL";
