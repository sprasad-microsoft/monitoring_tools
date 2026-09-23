// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <search.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nfs_diag.h"
#include "nfsiosnoop.skel.h"
#include "trace_helpers.c"

#define warn(...)	     fprintf(stderr, __VA_ARGS__)
#define pr_info(fmt, ...) \
    do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

static volatile sig_atomic_t exiting = 0;
static bool verbose = false;

static __u64 wakeup_data_size = 0;

static __u16 cmd_filter[MAX_NFS_COMMANDS];
static int cmd_filter_count = 0;
static bool cmd_filter_set = false;

static int err_filter[MAX_ERROR_CODES];
static int err_filter_count = 0;
static bool err_filter_set = false;

const char *argp_program_version = "nfsiosnoop 0.1";
const char *argp_program_bug_address = "https://github.com/meetakshi253/monitoring_tools";

static const struct argp_option opts[] = {
	{ "wakeupsize", 'w', "WAKEUPSIZE", 0, "Wake up the userspace handler" },
	{ "cmds", 'c', "CMDS", 0, "NFS4 commands to trace (comma-separated codes)" },
	{ "errors", 'e', "ERRORS", 0, "NFS error codes to trace (comma-separated, positive values)" },
	{ "verbose", 'v', NULL, 0, "Enable verbose output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int parse_cmd_list(const char *arg) {
	char *input = strdup(arg);
	if (!input)
		return -1;
	char *token = strtok(input, ",");
	while (token != NULL) {
		int cmd = atoi(token);
		if (cmd >= 0 && cmd < MAX_NFS_COMMANDS && cmd_filter_count < MAX_NFS_COMMANDS) {
			cmd_filter[cmd_filter_count++] = (__u16)cmd;
		}
		token = strtok(NULL, ",");
	}
	free(input);
	return cmd_filter_count;
}

static int compare_ints(const void *a, const void *b) {
	int val_a = *(const int *)a;
	int val_b = *(const int *)b;
	if (val_a < val_b) return -1;
	if (val_a > val_b) return 1;
	return 0;
}

static bool validate_err_code(int code) {
    return bsearch(&code, nfs4_errors, MAX_ERROR_CODES, sizeof(int), compare_ints) != NULL;
}

static int parse_err_list(const char *arg) {
	char *input = strdup(arg);
	if (!input)
		return -1;
	char *token = strtok(input, ",");
	while (token != NULL) {
		char *endptr;
		errno = 0;
		long code = strtol(token, &endptr, 10);
		if (*endptr != '\0' || errno != 0 || code <= 0) {
			warn("Invalid error code: %s\n", token);
			free(input);
			return -1;
		}
		if (validate_err_code((int)code) && err_filter_count < MAX_ERROR_CODES) {
			err_filter[err_filter_count++] = (int)code;
		} else if (!validate_err_code((int)code)) {
			warn("Unknown NFS error code: %ld\n", code);
		}
		token = strtok(NULL, ",");
	}
	free(input);
	return err_filter_count;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'w':
		errno = 0;
		wakeup_data_size = strtoll(arg, NULL, 10);
		if (errno) {
			warn("invalid wakeup data size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		cmd_filter_set = true;
		pr_info("Parsing command filter: %s\n", arg);
		int err = parse_cmd_list(arg);
		if (err < 0) {
			warn("Failed to parse commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		err_filter_set = true;
		pr_info("Parsing error filter: %s\n", arg);
		err = parse_err_list(arg);
		if (err < 0) {
			warn("Failed to parse error codes: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid error codes specified: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (!verbose && level > LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int update_allowlist_cmds(struct nfsiosnoop_bpf *skel) {
	__u8 val = 1;
	if (cmd_filter_set) {
		/* Only allow commands explicitly specified */
		for (int i = 0; i < cmd_filter_count; i++) {
			__u16 cmd = cmd_filter[i];
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowlist_cmds), &cmd, &val, BPF_ANY) < 0) {
				warn("Failed to update allowlist_cmds for command %d\n", cmd);
				return -1;
			}
		}
	} /* Else cmd_filter_set is false, so let through all commands */
	return 0;
}

static int update_allowlist_errors(struct nfsiosnoop_bpf *skel) {
	__u8 val = 1;
	if (err_filter_set) {
		/* Only allow error codes explicitly specified */
		for (int i = 0; i < err_filter_count; i++) {
			int code = err_filter[i];
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowlist_errors), &code, &val, BPF_ANY) < 0) {
				warn("Failed to update allowlist_errors for code %d\n", code);
				return -1;
			}
		}
	} /* Else err_filter_set is false, so let through all error codes */
	return 0;
}

/*
 * Raw tracepoint field offsets include the architecture/kernel trace header.
 * RHEL 9 exposes common_preempt_lazy_count in that header, shifting the NFS
 * payload by four bytes. Since raw tracepoint contexts have no CO-RE field
 * relocation, inspect the authoritative tracefs format and select the BPF
 * program compiled for that layout. The helper only detects record layout; it
 * neither tests whether lazy preemption is active nor changes scheduler state.
 */
static bool tracepoint_has_lazy_preempt(void)
{
	const char *paths[] = {
		"/sys/kernel/tracing/events/nfs4/nfs4_xdr_status/format",
		"/sys/kernel/debug/tracing/events/nfs4/nfs4_xdr_status/format",
	};
	char line[256];
	FILE *file;

	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		file = fopen(paths[i], "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, "common_preempt_lazy_count")) {
				fclose(file);
				return true;
			}
		}
		fclose(file);
	}
	return false;
}

int main(int argc, char **argv)
{
	struct nfsiosnoop_bpf *skel;
	bool lazy_preempt;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	if (!cmd_filter_set && !err_filter_set) {
		warn("Must specify at least one of --cmds or --errors\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	skel = nfsiosnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->wakeup_data_size = wakeup_data_size;
	skel->rodata->filter_errors = err_filter_set;
    skel->rodata->filter_cmds = cmd_filter_set;

	if (tracepoint_exists("nfs4", "nfs4_xdr_status")) {
		lazy_preempt = tracepoint_has_lazy_preempt();
		pr_info("Attaching to nfs4:nfs4_xdr_status\n");
		bpf_program__set_autoload(lazy_preempt ?
			skel->progs.trace_nfs4_xdr_status :
			skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoattach(lazy_preempt ?
			skel->progs.trace_nfs4_xdr_status :
			skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoload(skel->progs.rpc_done_exit, false);
		bpf_program__set_autoattach(skel->progs.rpc_done_exit, false);
		bpf_program__set_autoload(skel->progs.rpc_done_kprobe, false);
		bpf_program__set_autoattach(skel->progs.rpc_done_kprobe, false);
	} else if (fentry_can_attach("rpc_exit_task", "sunrpc")) {
		pr_info("Attaching to rpc_exit_task with fexit\n");
		bpf_program__set_autoload(skel->progs.trace_nfs4_xdr_status, false);
		bpf_program__set_autoattach(skel->progs.trace_nfs4_xdr_status, false);
		bpf_program__set_autoload(skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoattach(skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoload(skel->progs.rpc_done_kprobe, false);
		bpf_program__set_autoattach(skel->progs.rpc_done_kprobe, false);
	} else {
		pr_info("Attaching to rpc_exit_task with kprobe\n");
		bpf_program__set_autoload(skel->progs.trace_nfs4_xdr_status, false);
		bpf_program__set_autoattach(skel->progs.trace_nfs4_xdr_status, false);
		bpf_program__set_autoload(skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoattach(skel->progs.trace_nfs4_xdr_status_lazy, false);
		bpf_program__set_autoload(skel->progs.rpc_done_exit, false);
		bpf_program__set_autoattach(skel->progs.rpc_done_exit, false);
	}

	err = nfsiosnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (update_allowlist_cmds(skel) < 0) {
		fprintf(stderr, "Failed to update allowlist_cmds map\n");
		goto cleanup;
	}

	if (update_allowlist_errors(skel) < 0) {
		fprintf(stderr, "Failed to update allowlist_errors map\n");
		goto cleanup;
	}

    // print the allowed commands and errors for verification
    if (cmd_filter_set) {
        pr_info("Allowlist commands:\n");
        for (int i = 0; i < cmd_filter_count; i++) {
            pr_info("  %d\n", cmd_filter[i]);
        }
    }
    if (err_filter_set) {
        pr_info("Allowlist error codes:\n");
        for (int i = 0; i < err_filter_count; i++) {
            pr_info("  %d\n", err_filter[i]);
        }
    }

	err = nfsiosnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		goto cleanup;
	}

	pr_info("  Ring buffer: %s\n", RINGBUF_PINNED);
	pr_info("  Consume and detach from python. Ctrl+C to exit.\n");

	while (!exiting) {
		pause();
	}

cleanup:
	nfsiosnoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
