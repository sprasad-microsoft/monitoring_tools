#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ioslower.skel.h"

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

static volatile sig_atomic_t exiting = 0;

struct {
	bool verbose;
	int duration;
	__u64 min_us;
} opts = {
	.verbose = false,
	.duration = 0,
	.min_us = 10000,  /* Default 10ms threshold */
};

const char *argp_program_version = "ioslower 1.0";
const char *argp_program_bug_address = "<linux-diagnostics@microsoft.com>";
static const char argp_doc[] = "Trace slow filesystem I/O syscalls.\n";

static const struct argp_option opts_options[] = {
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{ "duration", 'd', "SECS", 0, "Trace for this many seconds" },
	{ "threshold", 'm', "MS", 0, "Latency threshold in milliseconds (default: 10)" },
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

int main(int argc, char **argv)
{
	struct ioslower_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	__u32 zero = 0;
	__u64 *config_val;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = ioslower_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = ioslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = ioslower_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Set latency threshold */
	err = bpf_map_update_elem(bpf_object__find_map_by_name(skel->obj, "config"),
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

	if (opts.duration) {
		sleep(opts.duration);
		exiting = 1;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	ioslower_bpf__destroy(skel);

	return err < 0 ? 1 : 0;
}
