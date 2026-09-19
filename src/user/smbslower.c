// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Developed by Meetakshi Setiya */
/* Copyright (c) 2026 Microsoft */
#define _POSIX_C_SOURCE 200809L
#include <argp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "smb_diag.h"
#include "smbslower.skel.h"
#include "trace_helpers.c"

#define warn(...)	     fprintf(stderr, __VA_ARGS__)
#define pr_info(fmt, ...) \
    do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

static volatile sig_atomic_t exiting = 0;
static bool verbose = false;
static bool skip_tracepoints = false;

static __u64 min_lat_ms = 10;
static __u64 wakeup_data_size = 0; /* used to wake up the user space handler */

static bool include_mode = false, exclude_mode = false;
static __u8 cmd_filter[MAX_SMB_COMMANDS] = {0};

const char *argp_program_version = "smbslower 0.1";
const char *argp_program_bug_address = "https://github.com/meetakshi253/monitoring_tools";

static const struct argp_option opts[] = {
	{ "wakeupsize", 'w', "WAKEUPSIZE", 0, "Wake up the userspace handler" },
	{ "include-cmds", 'c', "INCLUDE", 0, "Allowed SMB commands to trace" },
	{ "exclude-cmds", 'x', "EXCLUDE", 0, "SMB commands to exclude from tracing"},
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms (default 10)" },
	{ "skip-tracepoints", 1, NULL, 0, "Skip tracepoints and use function probes" },
	{ "verbose", 'v', NULL, 0, "Enable verbose output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int parse_cmd_list(const char *arg, int max_cmds) {
	int count = 0;
	char *input = strdup(arg);
	if (!input) {
		return -1;
	}
	char *token = strtok(input, ",");
	while (token != NULL && count < max_cmds) {
		int cmd = atoi(token);
		if (cmd >= 0 && cmd < MAX_SMB_COMMANDS) {
			cmd_filter[cmd] = 1;
			count++;
		}
		token = strtok(NULL, ",");
	}
	free(input);
	return count;
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
		if (exclude_mode) {
			warn("Cannot use --include-cmds with --exclude-cmds\n");
			argp_usage(state);
			return 1;
		}
		include_mode = true;
		pr_info("Include mode enabled, parsing commands: %s\n", arg);
		int err = parse_cmd_list(arg, MAX_SMB_COMMANDS);
		if (err < 0) {
			warn("Failed to parse include commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in include list: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'x':
		if (include_mode) {
			warn("Cannot use --exclude-cmds with --include-cmds\n");
			argp_usage(state);
			return 1;
		}
		exclude_mode = true;
		pr_info("Exclude mode enabled, parsing commands: %s\n", arg);
		err = parse_cmd_list(arg, MAX_SMB_COMMANDS);
		if (err < 0) {
			warn("Failed to parse exclude commands: %s\n", arg);
			argp_usage(state);
		} else if (err == 0) {
			warn("No valid commands specified in exclude list: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		min_lat_ms = strtoll(arg, NULL, 10);
		if (errno) {
			warn("invalid latency (in ms): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		verbose = true;
		break;
	case 1:
		skip_tracepoints = true;
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

int update_denylist_map(struct smbslower_bpf *skel) {
	for (__u16 cmd = 0; cmd < MAX_SMB_COMMANDS; cmd ++) {
		bool deny = false;
		if (exclude_mode && cmd_filter[cmd]) deny = true;
		else if (include_mode && !cmd_filter[cmd]) deny = true;

		if (deny) {
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.denylist), &cmd, &deny, BPF_ANY) < 0) {
				warn("Failed to update denylist map for command %d\n", cmd);
				return -1;
			}
		}
	}
	return 0;
}


int main(int argc, char **argv)
{
	struct smbslower_bpf *skel;
	int err, release_mid_params;
	bool can_attach_fentry, use_tracepoints;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	skel = smbslower_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->min_lat_ns = min_lat_ms * 1000 * 1000;
	skel->rodata->wakeup_data_size = wakeup_data_size;

	use_tracepoints = !skip_tracepoints &&
			  tracepoint_exists("cifs", "smb3_cmd_enter") &&
			  tracepoint_exists("cifs", "smb3_cmd_done") &&
			  tracepoint_exists("cifs", "smb3_cmd_err");
	if (skip_tracepoints)
		pr_info("Skipping CIFS tracepoints by request\n");
	if (use_tracepoints) {
		pr_info("Attaching to cifs:smb3_cmd_enter, smb3_cmd_done, and smb3_cmd_err\n");
		bpf_program__set_autoload(skel->progs.mid_alloc_fexit, false);
		bpf_program__set_autoattach(skel->progs.mid_alloc_fexit, false);
		bpf_program__set_autoattach(skel->progs.mid_alloc_kretprobe, false);
		bpf_program__set_autoload(skel->progs.mid_alloc_kretprobe, false);
	} else {
		bpf_program__set_autoload(skel->progs.trace_smb3_cmd_enter, false);
		bpf_program__set_autoattach(skel->progs.trace_smb3_cmd_enter, false);
		bpf_program__set_autoload(skel->progs.trace_smb3_cmd_done, false);
		bpf_program__set_autoattach(skel->progs.trace_smb3_cmd_done, false);
		bpf_program__set_autoload(skel->progs.trace_smb3_cmd_err, false);
		bpf_program__set_autoattach(skel->progs.trace_smb3_cmd_err, false);

		/* Use fexit if available, otherwise fall back to kretprobe. */
		if (fentry_can_attach("smb2_mid_entry_alloc", "cifs")) {
			pr_info("Attaching to smb2_mid_entry_alloc with fexit\n");
			bpf_program__set_autoattach(skel->progs.mid_alloc_kretprobe, false);
			bpf_program__set_autoload(skel->progs.mid_alloc_kretprobe, false);
		} else {
			pr_info("Attaching to smb2_mid_entry_alloc with kretprobe\n");
			bpf_program__set_autoattach(skel->progs.mid_alloc_fexit, false);
			bpf_program__set_autoload(skel->progs.mid_alloc_fexit, false);
		}
	}

	/* For __release_mid: disable auto-attach and auto-load for all four variants,
	 * we attach the correct one manually after load */
	bpf_program__set_autoload(skel->progs.mid_release_kref_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_kref_kprobe, false);
	bpf_program__set_autoload(skel->progs.mid_release_direct_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_direct_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_kref_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_kref_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_direct_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_direct_kprobe, false);

	/* Detect __release_mid signature via kernel version to avoid
	 * loading fentry programs with mismatched argument counts.
	 * Use fentry if available, otherwise fall back to kprobe. */
	release_mid_params = get_func_param_count("__release_mid", "cifs");
	can_attach_fentry = !use_tracepoints &&
			    fentry_can_attach("__release_mid", "cifs");

	if (use_tracepoints) {
		pr_info("CIFS function probes disabled in favor of tracepoints\n");
	} else if (can_attach_fentry) {
		if (release_mid_params >= 2) {
			pr_info("Attaching to __release_mid with fentry (server, mid)\n");
			bpf_program__set_autoload(skel->progs.mid_release_direct_fentry, true);
			bpf_program__set_autoattach(skel->progs.mid_release_direct_fentry, true);
		} else {
			pr_info("Attaching to __release_mid with fentry (struct kref *)\n");
			bpf_program__set_autoload(skel->progs.mid_release_kref_fentry, true);
			bpf_program__set_autoattach(skel->progs.mid_release_kref_fentry, true);
		}
	} else {
		if (release_mid_params >= 2) {
			pr_info("Attaching to __release_mid with kprobe (server, mid)\n");
			bpf_program__set_autoload(skel->progs.mid_release_direct_kprobe, true);
			bpf_program__set_autoattach(skel->progs.mid_release_direct_kprobe, true);
		} else {
			pr_info("Attaching to __release_mid with kprobe (struct kref *)\n");
			bpf_program__set_autoload(skel->progs.mid_release_kref_kprobe, true);
			bpf_program__set_autoattach(skel->progs.mid_release_kref_kprobe, true);
		}
	}

	err = smbslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	if (update_denylist_map(skel) < 0) {
		fprintf(stderr, "Failed to update denylist map\n");
		goto cleanup;
	}

	err = smbslower_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pr_info("  Ring buffer: %s\n", RINGBUF_PINNED);
	pr_info("  Consume and detach from python. Ctrl+C to exit.\n");

	while (!exiting) {
		pause();
	}

cleanup:
	smbslower_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}