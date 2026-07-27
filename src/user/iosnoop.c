#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iosnoop.skel.h"

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

static volatile sig_atomic_t exiting = 0;

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

const char *io_type_str(int type)
{
	switch (type) {
	case IO_OPEN:
		return "OPEN";
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
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct io_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	if (data_sz < sizeof(*e))
		return 1;

	t = e->ts / 1000000000;
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-6d %-16s %-12s %6d %-30s %s\n",
		ts,
		e->pid,
		e->comm,
		io_type_str(e->type),
		e->ret,
		e->args[0] ? e->args : "-",
		e->fname);

	return 0;
}

int main(int argc, char **argv)
{
	struct iosnoop_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	skel = iosnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = iosnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = iosnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	/* Setup mount filtering if specified */
	if (opts.mount_path) {
		struct stat st;
		__u32 dev_id = 0;
		__u32 value = 1;

		if (stat(opts.mount_path, &st) < 0) {
			perror("stat");
			goto cleanup;
		}

		dev_id = st.st_dev;
		err = bpf_map_update_elem(bpf_object__find_map_by_name(skel->obj, "mount_filter"),
					  &dev_id, &value, 0);
		if (err < 0) {
			fprintf(stderr, "Failed to set mount filter: %d\n", err);
			goto cleanup;
		}

		printf("Filtering by mount: %s (dev: %u)\n", opts.mount_path, dev_id);
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
	iosnoop_bpf__destroy(skel);

	return err < 0 ? 1 : 0;
}
