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
#include "ioslower.skel.h"
#include "trace_helpers.c"

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
/* Memory mapping syscalls */
#define SC_MMAP		45
#define SC_MMAP2		46
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

static volatile sig_atomic_t exiting = 0;

static char mount_path_resolved[PATH_MAX];
static dev_t mount_dev_id;

struct {
	bool verbose;
	int duration;
	__u64 min_us;
	char *mount_path;
} opts = {
	.verbose = false,
	.duration = 0,
	.min_us = 10000,  /* Default 10ms threshold */
	.mount_path = NULL,
};

const char *argp_program_version = "ioslower 1.0";
const char *argp_program_bug_address = "<linux-diagnostics@microsoft.com>";
static const char argp_doc[] = "Trace slow filesystem I/O syscalls.\n";

static const struct argp_option opts_options[] = {
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{ "duration", 'd', "SECS", 0, "Trace for this many seconds" },
	{ "threshold", 'm', "MS", 0, "Latency threshold in milliseconds (default: 10)" },
	{ "mount", 'p', "PATH", 0, "Filter by mount path" },
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
		opts.min_us = strtol(arg, NULL, 10) * 1000;  /* Convert ms to us */
		break;
	case 'p':
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

const char *syscall_name(int type)
{
	switch (type) {
	case SC_OPEN:
		return "open";
	case SC_OPENAT:
		return "openat";
	case SC_READ:
		return "read";
	case SC_WRITE:
		return "write";
	case SC_CLOSE:
		return "close";
	case SC_STAT:
		return "stat";
	case SC_LSTAT:
		return "lstat";
	case SC_FSTAT:
		return "fstat";
	case SC_MKDIR:
		return "mkdir";
	case SC_MKDIRAT:
		return "mkdirat";
	case SC_RMDIR:
		return "rmdir";
	case SC_UNLINK:
		return "unlink";
	case SC_UNLINKAT:
		return "unlinkat";
	case SC_RENAME:
		return "rename";
	case SC_RENAMEAT:
		return "renameat";
	case SC_RENAMEAT2:
		return "renameat2";
	case SC_MOUNT:
		return "mount";
	case SC_UMOUNT2:
		return "umount2";
	case SC_CHMOD:
		return "chmod";
	case SC_FCHMOD:
		return "fchmod";
	case SC_CHOWN:
		return "chown";
	case SC_FCHOWN:
		return "fchown";
	case SC_TRUNCATE:
		return "truncate";
	case SC_FTRUNCATE:
		return "ftruncate";
	case SC_LINK:
		return "link";
	case SC_LINKAT:
		return "linkat";
	case SC_SYMLINK:
		return "symlink";
	case SC_SYMLINKAT:
		return "symlinkat";
	case SC_READLINK:
		return "readlink";
	case SC_READLINKAT:
		return "readlinkat";
	case SC_PREAD64:
		return "pread64";
	case SC_PWRITE64:
		return "pwrite64";
	case SC_READV:
		return "readv";
	case SC_WRITEV:
		return "writev";
	case SC_PREADV:
		return "preadv";
	case SC_PWRITEV:
		return "pwritev";
	case SC_URING_ENTER:
		return "uring_enter";
	case SC_URING_SETUP:
		return "uring_setup";
	case SC_URING_REGISTER:
		return "uring_register";
	case SC_SETUP:
		return "io_setup";
	case SC_SUBMIT:
		return "io_submit";
	case SC_GETEVENTS:
		return "io_getevents";
	case SC_CANCEL:
		return "io_cancel";
	case SC_DESTROY:
		return "io_destroy";
	case SC_MMAP:
		return "mmap";
	case SC_MMAP2:
		return "mmap2";
	case SC_MUNMAP:
		return "munmap";
	case SC_CREATE:
		return "create";
	case SC_FALLOCATE:
		return "fallocate";
	case SC_GETDENTS:
		return "getdents";
	case SC_LOCK_FCNTL:
		return "lock_fcntl";
	case SC_LOCK_FLOCK:
		return "lock_flock";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct ioslower_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(*e))
		return 1;

	t = e->ts / 1000000000;
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-6d %-16s %-12s %9u.%03u %-8s %s\n",
		ts,
		e->pid,
		e->comm,
		syscall_name(e->type),
		e->delta_us / 1000,
		e->delta_us % 1000,
		e->ret >= 0 ? "OK" : "ERR",
		e->fname);

	return 0;
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

static void select_vfs_hook_family(struct ioslower_bpf *skel)
{
	struct bpf_program *program;
	bool use_fentry = vfs_fentry_family_supported();
	/*
	 * Older enterprise kernels expose vfs_create with four arguments and
	 * vfs_rename with six direct arguments. New kernels use five arguments
	 * for vfs_create and a single struct renamedata for vfs_rename. This is
	 * kernel ABI compatibility, not a distro-name check: select from BTF
	 * parameter counts and do not load probes for symbols absent at runtime.
	 */
	bool legacy_vfs_create = get_func_param_count("vfs_create", NULL) == 4;
	bool legacy_vfs_rename = get_func_param_count("vfs_rename", NULL) == 6;

	bpf_object__for_each_program(program, skel->obj) {
		const char *name = bpf_program__name(program);
		const char *section = bpf_program__section_name(program);
		bool fentry_program = !strncmp(section, "fentry/", 7) ||
				      !strncmp(section, "fexit/", 6);
		bool fallback_program = strstr(name, "_fallback") != NULL;
		bool legacy_program = strstr(name, "_legacy_fallback") != NULL;

		if (fentry_program) {
			bpf_program__set_autoload(program, use_fentry);
			bpf_program__set_autoattach(program, use_fentry);
		} else if (fallback_program) {
			bool enable = !use_fentry;
			const char *target = strchr(section, '/');

			if (target && !kernel_function_exists(target + 1))
				enable = false;

			if (strstr(name, "vfs_rename_legacy_kprobe_fallback"))
				enable = enable && legacy_vfs_rename;
			else if (strstr(name, "vfs_rename_kprobe_fallback"))
				enable = enable && !legacy_vfs_rename;
			else if (strstr(name, "vfs_create_kprobe_fallback"))
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

int main(int argc, char **argv)
{
	struct ioslower_bpf *skel;
	struct ring_buffer *rb = NULL;
	struct mount_filter_cfg filter_cfg = {};
	int err;
	__u32 zero = 0;

	/* Unbuffered stdout so every event line reaches files/pipes immediately */
	setvbuf(stdout, NULL, _IONBF, 0);

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = ioslower_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	select_vfs_hook_family(skel);

	err = ioslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

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

	err = ioslower_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Set latency threshold */
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.threshold_config),
				  &zero, &opts.min_us, 0);
	if (err < 0) {
		fprintf(stderr, "Failed to set threshold: %d\n", err);
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

	printf("Tracing filesystem syscalls slower than %llu.%03llu ms...\n",
		opts.min_us / 1000, opts.min_us % 1000);
	printf("%-8s %-6s %-16s %-12s %-10s %-8s %s\n",
		"TIME", "PID", "COMM", "SYSCALL", "LATENCY(ms)", "STATUS", "PATH");

	time_t deadline = opts.duration ? time(NULL) + opts.duration : 0;

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		if (deadline && time(NULL) >= deadline)
			break;
	}

cleanup:
	ring_buffer__free(rb);
	ioslower_bpf__destroy(skel);

	return err < 0 ? 1 : 0;
}
