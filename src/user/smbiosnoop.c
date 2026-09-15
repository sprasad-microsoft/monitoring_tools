// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Microsoft */
#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "smb_diag.h"
#include "smbiosnoop.skel.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(fmt, ...) \
	do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

static volatile sig_atomic_t exiting;
static bool verbose;
static __u64 wakeup_data_size;

static __u16 cmd_filter[MAX_SMB_COMMANDS];
static int cmd_filter_count;
static bool cmd_filter_set;

static __u32 err_filter[MAX_SMB_STATUS_CODES];
static int err_filter_count;
static bool err_filter_set;

const char *argp_program_version = "smbiosnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/meetakshi253/monitoring_tools";

static const struct argp_option opts[] = {
	{ "wakeupsize", 'w', "WAKEUPSIZE", 0, "Wake up the userspace handler" },
	{ "cmds", 'c', "CMDS", 0, "SMB2 commands to trace (comma-separated codes)" },
	{ "errors", 'e', "ERRORS", 0, "NTSTATUS values to trace (decimal or 0x-prefixed)" },
	{ "verbose", 'v', NULL, 0, "Enable verbose output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int parse_cmd_list(const char *arg)
{
	char *input = strdup(arg);
	char *token;

	if (!input)
		return -1;

	token = strtok(input, ",");
	while (token) {
		char *end;
		long command;

		errno = 0;
		command = strtol(token, &end, 0);
		if (errno || *end || command < 0 || command >= MAX_SMB_COMMANDS) {
			warn("Invalid SMB command: %s\n", token);
			free(input);
			return -1;
		}
		if (cmd_filter_count >= MAX_SMB_COMMANDS) {
			warn("Too many SMB commands\n");
			free(input);
			return -1;
		}
		cmd_filter[cmd_filter_count++] = (__u16)command;
		token = strtok(NULL, ",");
	}

	free(input);
	return cmd_filter_count;
}

static int parse_err_list(const char *arg)
{
	char *input = strdup(arg);
	char *token;

	if (!input)
		return -1;

	token = strtok(input, ",");
	while (token) {
		char *end;
		unsigned long long status;

		errno = 0;
		status = strtoull(token, &end, 0);
		if (errno || *end || !status || status > UINT32_MAX) {
			warn("Invalid NTSTATUS value: %s\n", token);
			free(input);
			return -1;
		}
		if (err_filter_count >= MAX_SMB_STATUS_CODES) {
			warn("Too many NTSTATUS values\n");
			free(input);
			return -1;
		}
		err_filter[err_filter_count++] = (__u32)status;
		token = strtok(NULL, ",");
	}

	free(input);
	return err_filter_count;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int count;

	switch (key) {
	case 'w':
		errno = 0;
		wakeup_data_size = strtoull(arg, NULL, 10);
		if (errno) {
			warn("Invalid wakeup data size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'c':
		cmd_filter_set = true;
		count = parse_cmd_list(arg);
		if (count <= 0) {
			warn("No valid SMB commands specified: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'e':
		err_filter_set = true;
		count = parse_err_list(arg);
		if (count <= 0) {
			warn("No valid NTSTATUS values specified: %s\n", arg);
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (!verbose && level > LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int update_allowlist_cmds(struct smbiosnoop_bpf *skel)
{
	__u8 allowed = 1;

	for (int i = 0; i < cmd_filter_count; i++) {
		__u16 command = cmd_filter[i];

		if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowlist_cmds),
					&command, &allowed, BPF_ANY) < 0) {
			warn("Failed to allow SMB command %u\n", command);
			return -1;
		}
	}

	return 0;
}

static int update_allowlist_errors(struct smbiosnoop_bpf *skel)
{
	__u8 allowed = 1;

	for (int i = 0; i < err_filter_count; i++) {
		__u32 status = err_filter[i];

		if (bpf_map_update_elem(bpf_map__fd(skel->maps.allowlist_errors),
					&status, &allowed, BPF_ANY) < 0) {
			warn("Failed to allow NTSTATUS 0x%08x\n", status);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct smbiosnoop_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (!cmd_filter_set && !err_filter_set) {
		warn("Must specify at least one of --cmds or --errors\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	skel = smbiosnoop_bpf__open();
	if (!skel) {
		warn("Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->wakeup_data_size = wakeup_data_size;
	skel->rodata->filter_errors = err_filter_set;
	skel->rodata->filter_cmds = cmd_filter_set;

	err = smbiosnoop_bpf__load(skel);
	if (err) {
		warn("Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (update_allowlist_cmds(skel) < 0 ||
	    update_allowlist_errors(skel) < 0) {
		err = -1;
		goto cleanup;
	}

	err = smbiosnoop_bpf__attach(skel);
	if (err) {
		warn("Failed to attach BPF programs\n");
		goto cleanup;
	}

	pr_info("  Ring buffer: %s\n", RINGBUF_PINNED);
	pr_info("  Consume and detach from Python. Ctrl+C to exit.\n");
	while (!exiting)
		pause();

cleanup:
	smbiosnoop_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}