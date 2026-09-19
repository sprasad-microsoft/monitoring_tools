#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iosnoop.skel.h"
#include "trace_helpers.c"

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
#define IO_CREATE	48
#define IO_FALLOCATE	49
#define IO_GETDENTS	50
#define IO_LOCK_FCNTL	51
#define IO_LOCK_FLOCK	52

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

struct mount_filter_cfg {
	__u32 enabled;
	__u32 dev_major;
	__u32 dev_minor;
};

static volatile sig_atomic_t exiting = 0;

static char mount_path_resolved[PATH_MAX];
static dev_t mount_dev_id;

struct {
	bool verbose;
	int duration;
	char *mount_path;
} opts = {
	.verbose = false,
	.duration = 0,
	.mount_path = NULL,
};

const char *argp_program_version = "iosnoop 1.0";
const char *argp_program_bug_address = "<linux-diagnostics@microsoft.com>";
static const char argp_doc[] = "Trace filesystem I/O syscalls.\n";

static const struct argp_option opts_options[] = {
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{ "duration", 'd', "SECS", 0, "Trace for this many seconds" },
	{ "mount", 'm', "PATH", 0, "Filter by mount path" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		opts.verbose = true;
		break;
	case 'd':
		opts.duration = strtol(arg, NULL, 10);
		if (opts.duration <= 0)
			opts.duration = 0;
		break;
	case 'm':
		opts.mount_path = strdup(arg);
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts_options,
	.parser = parse_arg,
	.doc = argp_doc,
};

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !opts.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

struct vfs_hook_spec {
	const char *name;
	int parameter_count;
};

static const struct vfs_hook_spec vfs_hooks[] = {
	{ "vfs_open", 2 },
	{ "vfs_read", 4 },
	{ "vfs_write", 4 },
	{ "vfs_create", 5 },
	{ "vfs_mkdir", 4 },
	{ "vfs_rmdir", 3 },
	{ "vfs_symlink", 4 },
	{ "vfs_rename", 1 },
	{ "vfs_getattr", 4 },
	{ "vfs_truncate", 2 },
	{ "vfs_fchmod", 2 },
	{ "vfs_readlink", 3 },
	{ "vfs_readv", 5 },
	{ "vfs_writev", 5 },
	{ "iterate_dir", 2 },
	{ "vfs_lock_file", 4 },
};

static bool vfs_fentry_family_supported(void)
{
	size_t index;

	for (index = 0; index < sizeof(vfs_hooks) / sizeof(vfs_hooks[0]); index++) {
		if (!fentry_can_attach(vfs_hooks[index].name, NULL) ||
		    get_func_param_count(vfs_hooks[index].name, NULL) !=
			    vfs_hooks[index].parameter_count)
			return false;
	}

	return true;
}

static void select_vfs_hook_family(struct iosnoop_bpf *skel)
{
	struct bpf_program *program;
	bool use_fentry = vfs_fentry_family_supported();
	bool legacy_vfs_create = get_func_param_count("vfs_create", NULL) == 4;

	bpf_object__for_each_program(program, skel->obj) {
		const char *name = bpf_program__name(program);
		const char *section = bpf_program__section_name(program);
		bool syscall_program = !strncmp(section, "tracepoint/syscalls/", 20) ||
				       !strncmp(section, "kprobe/__x64_sys_", 17) ||
				       !strncmp(section, "kretprobe/__x64_sys_", 20);
		bool fentry_program = !strncmp(section, "fentry/", 7) ||
				      !strncmp(section, "fexit/", 6);
		bool fallback_program = strstr(name, "_fallback") != NULL;
		bool legacy_program = strstr(name, "_legacy_fallback") != NULL;

		if (syscall_program) {
			bpf_program__set_autoload(program, false);
			bpf_program__set_autoattach(program, false);
		} else if (fentry_program) {
			bpf_program__set_autoload(program, use_fentry);
			bpf_program__set_autoattach(program, use_fentry);
		} else if (fallback_program) {
			bool enable = !use_fentry;

			if (strstr(name, "vfs_create_kprobe_fallback"))
				enable = enable && !legacy_vfs_create;
			else if (legacy_program)
				enable = enable && legacy_vfs_create;
			bpf_program__set_autoload(program, enable);
			bpf_program__set_autoattach(program, enable);
		}
	}

	if (use_fentry)
		fprintf(stderr, "Using VFS fentry/fexit probes\n");
	else
		fprintf(stderr, "Using VFS kprobe/kretprobe fallbacks\n");
}

struct fd_path_entry {
	__u32 pid;
	int fd;
	char path[256];
	struct fd_path_entry *next;
};

static struct fd_path_entry *fd_paths;

static bool is_fd_based_type(__u8 type)
{
	switch (type) {
	case IO_READ:
	case IO_WRITE:
	case IO_CLOSE:
	case IO_FSTAT:
	case IO_FCHMOD:
	case IO_FCHOWN:
	case IO_FTRUNCATE:
	case IO_PREAD64:
	case IO_PWRITE64:
	case IO_READV:
	case IO_WRITEV:
	case IO_PREADV:
	case IO_PWRITEV:
		return true;
	default:
		return false;
	}
}

static int parse_fd_from_args(const char *args)
{
	char *end;
	long val;

	if (!args)
		return -1;
	if (strncmp(args, "fd=", 3) != 0)
		return -1;

	val = strtol(args + 3, &end, 10);
	if (end == args + 3)
		return -1;
	if (val < 0 || val > INT_MAX)
		return -1;

	return (int)val;
}

static const char *fd_path_lookup(__u32 pid, int fd)
{
	struct fd_path_entry *it = fd_paths;

	while (it) {
		if (it->pid == pid && it->fd == fd)
			return it->path;
		it = it->next;
	}

	return NULL;
}

static void fd_path_set(__u32 pid, int fd, const char *path)
{
	struct fd_path_entry *it = fd_paths;
	struct fd_path_entry *entry;

	if (!path || !path[0] || fd < 0)
		return;

	while (it) {
		if (it->pid == pid && it->fd == fd) {
			snprintf(it->path, sizeof(it->path), "%s", path);
			return;
		}
		it = it->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->pid = pid;
	entry->fd = fd;
	snprintf(entry->path, sizeof(entry->path), "%s", path);
	entry->next = fd_paths;
	fd_paths = entry;
}

static void fd_path_del(__u32 pid, int fd)
{
	struct fd_path_entry **pp = &fd_paths;

	while (*pp) {
		if ((*pp)->pid == pid && (*pp)->fd == fd) {
			struct fd_path_entry *victim = *pp;
			*pp = victim->next;
			free(victim);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void fd_path_free_all(void)
{
	struct fd_path_entry *it = fd_paths;

	while (it) {
		struct fd_path_entry *next = it->next;
		free(it);
		it = next;
	}
	fd_paths = NULL;
}

const char *io_type_str(int type)
{
	switch (type) {
	case IO_OPEN:
		return "OPEN";
	case IO_OPENAT:
		return "OPENAT";
	case IO_READ:
		return "READ";
	case IO_WRITE:
		return "WRITE";
	case IO_CLOSE:
		return "CLOSE";
	case IO_STAT:
		return "STAT";
	case IO_LSTAT:
		return "LSTAT";
	case IO_FSTAT:
		return "FSTAT";
	case IO_MKDIR:
		return "MKDIR";
	case IO_MKDIRAT:
		return "MKDIRAT";
	case IO_RMDIR:
		return "RMDIR";
	case IO_UNLINK:
		return "UNLINK";
	case IO_UNLINKAT:
		return "UNLINKAT";
	case IO_RENAME:
		return "RENAME";
	case IO_RENAMEAT:
		return "RENAMEAT";
	case IO_RENAMEAT2:
		return "RENAMEAT2";
	case IO_MOUNT:
		return "MOUNT";
	case IO_UMOUNT2:
		return "UMOUNT2";
	case IO_CHMOD:
		return "CHMOD";
	case IO_FCHMOD:
		return "FCHMOD";
	case IO_CHOWN:
		return "CHOWN";
	case IO_FCHOWN:
		return "FCHOWN";
	case IO_TRUNCATE:
		return "TRUNCATE";
	case IO_FTRUNCATE:
		return "FTRUNCATE";
	case IO_LINK:
		return "LINK";
	case IO_LINKAT:
		return "LINKAT";
	case IO_SYMLINK:
		return "SYMLINK";
	case IO_SYMLINKAT:
		return "SYMLINKAT";
	case IO_READLINK:
		return "READLINK";
	case IO_READLINKAT:
		return "READLINKAT";
	case IO_PREAD64:
		return "PREAD64";
	case IO_PWRITE64:
		return "PWRITE64";
	case IO_READV:
		return "READV";
	case IO_WRITEV:
		return "WRITEV";
	case IO_PREADV:
		return "PREADV";
	case IO_PWRITEV:
		return "PWRITEV";
	case IO_URING_ENTER:
		return "URING_ENTER";
	case IO_URING_SETUP:
		return "URING_SETUP";
	case IO_URING_REGISTER:
		return "URING_REGISTER";
	case IO_SETUP:
		return "IO_SETUP";
	case IO_SUBMIT:
		return "IO_SUBMIT";
	case IO_GETEVENTS:
		return "IO_GETEVENTS";
	case IO_CANCEL:
		return "IO_CANCEL";
	case IO_DESTROY:
		return "IO_DESTROY";
	case IO_MMAP:
		return "MMAP";
	case IO_MMAP2:
		return "MMAP2";
	case IO_MUNMAP:
		return "MUNMAP";
	case IO_CREATE:
		return "CREATE";
	case IO_FALLOCATE:
		return "FALLOCATE";
	case IO_GETDENTS:
		return "GETDENTS";
	case IO_LOCK_FCNTL:
		return "LOCK_FCNTL";
	case IO_LOCK_FLOCK:
		return "LOCK_FLOCK";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct io_event *e = data;
	char args_disp[256];
	const char *path_disp = e->fname;
	const char *mapped_path;
	int fd = -1;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(*e))
		return 1;

	t = e->ts / 1000000000;
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->args[0]) {
		snprintf(args_disp, sizeof(args_disp), "%s", e->args);
	} else {
		snprintf(args_disp, sizeof(args_disp), "-");
	}

	if ((e->type == IO_OPEN || e->type == IO_OPENAT) && e->ret >= 0)
		fd_path_set(e->pid, e->ret, e->fname);

	fd = parse_fd_from_args(e->args);
	if (fd >= 0 && is_fd_based_type(e->type)) {
		snprintf(args_disp, sizeof(args_disp), "fd=%d", fd);
		mapped_path = fd_path_lookup(e->pid, fd);
		if (mapped_path)
			path_disp = mapped_path;
	}

	printf("%-8s %-6d %-16s %-12s %6d %-30s %s\n",
		ts,
		e->pid,
		e->comm,
		io_type_str(e->type),
		e->ret,
		args_disp,
		path_disp);

	if (e->type == IO_CLOSE && fd >= 0)
		fd_path_del(e->pid, fd);

	return 0;
}

int main(int argc, char **argv)
{
	struct iosnoop_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct mount_filter_cfg filter_cfg = {};
	__u32 zero = 0;
	int err;

	/* Unbuffered stdout so every event line reaches files/pipes immediately */
	setvbuf(stdout, NULL, _IONBF, 0);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = iosnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	select_vfs_hook_family(skel);

	err = iosnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Setup mount filtering if specified */
	if (opts.mount_path) {
		struct stat st;

		if (!realpath(opts.mount_path, mount_path_resolved)) {
			perror("realpath");
			goto cleanup;
		}

		if (stat(mount_path_resolved, &st) < 0) {
			perror("stat");
			goto cleanup;
		}
		mount_dev_id = st.st_dev;

		printf("Filtering by mount path: %s (dev: %lu)\n",
			mount_path_resolved, (unsigned long)mount_dev_id);

		filter_cfg.enabled = 1;
		filter_cfg.dev_major = (__u32)major(mount_dev_id);
		filter_cfg.dev_minor = (__u32)minor(mount_dev_id);
		printf("Mount filter device components: major=%u minor=%u\n",
			filter_cfg.dev_major, filter_cfg.dev_minor);
		err = bpf_map_update_elem(bpf_map__fd(skel->maps.mount_filter_cfg),
					  &zero, &filter_cfg, 0);
		if (err < 0) {
			fprintf(stderr, "Failed to configure mount filter: %d\n", err);
			goto cleanup;
		}
	}

	err = iosnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	printf("%-8s %-6s %-16s %-12s %6s %-30s %s\n",
		"TIME", "PID", "COMM", "TYPE", "RET", "ARGS", "PATH");

	time_t deadline = opts.duration ? time(NULL) + opts.duration : 0;

	while (!exiting) {
		err = ring_buffer__poll(rb, 10);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		if (deadline && time(NULL) >= deadline)
			break;
	}

cleanup:
	ring_buffer__free(rb);
	iosnoop_bpf__destroy(skel);
	fd_path_free_all();

	return err < 0 ? 1 : 0;
}
