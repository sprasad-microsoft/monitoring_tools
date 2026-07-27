#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "aiosnoop.skel.h"

/* Async I/O syscall types */
#define AIO_URING_ENTER		1
#define AIO_URING_SETUP		2
#define AIO_URING_REGISTER	3
#define AIO_SETUP		4
#define AIO_SUBMIT		5
#define AIO_GETEVENTS		6
#define AIO_CANCEL		7
#define AIO_DESTROY		8

struct aio_event {
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
	char args[256];
};

const char *aio_type_str(int type)
{
	switch (type) {
	case AIO_URING_ENTER:
		return "uring_enter";
	case AIO_URING_SETUP:
		return "uring_setup";
	case AIO_URING_REGISTER:
		return "uring_register";
	case AIO_SETUP:
		return "io_setup";
	case AIO_SUBMIT:
		return "io_submit";
	case AIO_GETEVENTS:
		return "io_getevents";
	case AIO_CANCEL:
		return "io_cancel";
	case AIO_DESTROY:
		return "io_destroy";
	default:
		return "UNKNOWN";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct aio_event *e = data;
	struct tm *tm;
	char buf[256];
	time_t t;

	t = e->ts / 1000000000;
	tm = localtime(&t);
	strftime(buf, sizeof(buf), "%H:%M:%S", tm);

	printf("%-8s %-6u %-16s %-16s %6d %-256s\n",
	       buf,
	       e->pid,
	       e->comm,
	       aio_type_str(e->type),
	       e->ret,
	       e->args);

	return 0;
}

static volatile bool exiting = false;

static void sig_int(int signo)
{
	exiting = true;
}

static const char *argp_program_version = "aiosnoop 1.0";
static const char *argp_program_bug_address = "<linux-cifs@vger.kernel.org>";
static const char argp_program_doc[] =
"Trace io_uring and libaio async I/O syscalls.\n"
"\n"
"USAGE: aiosnoop [-v] [-d DURATION]\n"
"EXAMPLES:\n"
"    aiosnoop              # trace all async I/O syscalls\n"
"    aiosnoop -v           # verbose output\n"
"    aiosnoop -d 30        # trace for 30 seconds\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{ "duration", 'd', "SECS", 0, "Trace duration" },
	{},
};

struct arguments {
	bool verbose;
	int duration;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	case 'v':
		arguments->verbose = true;
		break;
	case 'd':
		arguments->duration = atoi(arg);
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

int main(int argc, char **argv)
{
	struct arguments arguments = {};
	struct aiosnoop_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	time_t start_time = 0;

	arguments.duration = 0;

	/* Parse command line */
	err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (err)
		return err;

	/* Bump RLIMIT_MEMLOCK to allow BPF to run */
	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %s\n", strerror(-err));
		return 1;
	}

	/* Open and load BPF object */
	skel = aiosnoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	/* Attach BPF programs */
	err = aiosnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	if (arguments.verbose)
		printf("Attached BPF programs\n");

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(-err));
		goto cleanup;
	}

	/* Print header */
	printf("%-8s %-6s %-16s %-16s %6s %-256s\n",
	       "TIME", "PID", "COMM", "SYSCALL", "RET", "ARGS");

	/* Set signal handler */
	signal(SIGINT, sig_int);

	/* Record start time */
	start_time = time(NULL);

	/* Polling loop */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR)
			continue;
		if (err < 0) {
			printf("Error polling ring buffer: %s\n", strerror(-err));
			break;
		}

		if (arguments.duration && time(NULL) - start_time >= arguments.duration)
			break;
	}

cleanup:
	ring_buffer__free(rb);
	aiosnoop_bpf__destroy(skel);

	return err < 0 ? 1 : 0;
}
