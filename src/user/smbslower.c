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
#include <sys/wait.h>
#include <sys/utsname.h>

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

static bool file_equals(const char *path, const char *expected)
{
	char value[128];
	FILE *file = fopen(path, "r");

	if (!file)
		return false;
	if (!fgets(value, sizeof(value), file)) {
		fclose(file);
		return false;
	}
	fclose(file);
	value[strcspn(value, "\r\n")] = '\0';
	return strcmp(value, expected) == 0;
}

static int run_modprobe(const char *path)
{
	pid_t pid;
	pid_t waited;
	int status;

	if (access(path, X_OK) != 0)
		return -ENOENT;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		execl(path, path, "cifs", (char *)NULL);
		_exit(126);
	}

	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;
	return 0;
}

static int ensure_cifs_module_loaded(void)
{
	static const char *const modprobe_paths[] = {
		"/usr/sbin/modprobe",
		"/sbin/modprobe",
	};
	int err = -ENOENT;

	if (access("/sys/module/cifs", F_OK) == 0)
		return 0;
	for (size_t i = 0; i < sizeof(modprobe_paths) / sizeof(modprobe_paths[0]); i++) {
		err = run_modprobe(modprobe_paths[i]);
		if (!err)
			return 0;
	}
	return err;
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
	struct bpf_program *release_prog;
	const char *release_func = "__release_mid";
	int err, release_mid_params;
	bool can_attach_fentry, legacy_release = false, single_direct_release = false;
	bool rhel810_no_module_btf = false;
	struct utsname uts = {};

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

	err = ensure_cifs_module_loaded();
	if (err)
		pr_info("Unable to load the CIFS module before BTF inspection: %s\n",
			strerror(-err));

	bpf_program__set_autoload(skel->progs.mid_alloc_rhel810_kretprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_alloc_rhel810_kretprobe, false);
	if (access("/sys/kernel/btf/cifs", R_OK) != 0) {
		if (uname(&uts) != 0 ||
		    strcmp(uts.release, "4.18.0-553.el8_10.x86_64") != 0 ||
		    !file_equals("/sys/module/cifs/srcversion",
				 "77983F3F095C933642E503B")) {
			fprintf(stderr,
				"CIFS module BTF is unavailable and kernel/module %s has no verified fixed layout\n",
				uts.release[0] ? uts.release : "unknown");
			err = -ENOTSUP;
			goto cleanup;
		}
		rhel810_no_module_btf = true;
	}

	/* For mid_alloc: use fexit if fentry works, otherwise fall back to kretprobe */
	if (rhel810_no_module_btf) {
		pr_info("Attaching to smb2_mid_entry_alloc with verified RHEL 8.10 fixed-layout kretprobe\n");
		bpf_program__set_autoload(skel->progs.mid_alloc_fexit, false);
		bpf_program__set_autoattach(skel->progs.mid_alloc_fexit, false);
		bpf_program__set_autoload(skel->progs.mid_alloc_kretprobe, false);
		bpf_program__set_autoattach(skel->progs.mid_alloc_kretprobe, false);
		bpf_program__set_autoload(skel->progs.mid_alloc_rhel810_kretprobe, true);
		bpf_program__set_autoattach(skel->progs.mid_alloc_rhel810_kretprobe, true);
	} else if (fentry_can_attach("smb2_mid_entry_alloc", "cifs")) {
		pr_info("Attaching to smb2_mid_entry_alloc with fexit\n");
		bpf_program__set_autoattach(skel->progs.mid_alloc_kretprobe, false);
		bpf_program__set_autoload(skel->progs.mid_alloc_kretprobe, false);
	} else {
		pr_info("Attaching to smb2_mid_entry_alloc with kretprobe\n");
		bpf_program__set_autoattach(skel->progs.mid_alloc_fexit, false);
		bpf_program__set_autoload(skel->progs.mid_alloc_fexit, false);
	}

	/* Load and attach only the release variant matching the running CIFS module. */
	bpf_program__set_autoload(skel->progs.mid_release_kref_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_kref_kprobe, false);
	bpf_program__set_autoload(skel->progs.mid_release_direct_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_direct_kprobe, false);
	bpf_program__set_autoload(skel->progs.mid_release_legacy_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_legacy_kprobe, false);
	bpf_program__set_autoload(skel->progs.mid_release_rhel810_kprobe, false);
	bpf_program__set_autoload(skel->progs.mid_release_single_direct_fentry, false);
	bpf_program__set_autoload(skel->progs.mid_release_single_direct_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_kref_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_kref_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_direct_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_direct_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_legacy_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_legacy_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_rhel810_kprobe, false);
	bpf_program__set_autoattach(skel->progs.mid_release_single_direct_fentry, false);
	bpf_program__set_autoattach(skel->progs.mid_release_single_direct_kprobe, false);

	if (rhel810_no_module_btf) {
		release_func = "_cifs_mid_q_entry_release";
		legacy_release = true;
		release_mid_params = 1;
	} else {
		release_mid_params = get_func_param_count(release_func, "cifs");
	}
	if (release_mid_params == -ENOENT) {
		release_func = "release_mid";
		release_mid_params = get_func_param_count(release_func, "cifs");
		single_direct_release = release_mid_params == 1;
	}
	if (release_mid_params == -ENOENT) {
		release_func = "_cifs_mid_q_entry_release";
		legacy_release = true;
		release_mid_params = get_func_param_count(release_func, "cifs");
	}
	if ((release_mid_params != 1 && release_mid_params != 2) ||
	    (legacy_release && release_mid_params != 1)) {
		fprintf(stderr, "Unsupported CIFS release function %s: BTF parameter count %d\n",
			release_func, release_mid_params);
		err = -ENOTSUP;
		goto cleanup;
	}
	can_attach_fentry = access("/sys/kernel/btf/cifs", R_OK) == 0 &&
		fentry_can_attach(release_func, "cifs");
	if (rhel810_no_module_btf) {
		release_prog = skel->progs.mid_release_rhel810_kprobe;
		can_attach_fentry = false;
	} else if (single_direct_release) {
		release_prog = can_attach_fentry ?
			skel->progs.mid_release_single_direct_fentry :
			skel->progs.mid_release_single_direct_kprobe;
	} else if (legacy_release) {
		release_prog = can_attach_fentry ? skel->progs.mid_release_legacy_fentry :
			skel->progs.mid_release_legacy_kprobe;
	} else if (release_mid_params == 2) {
		release_prog = can_attach_fentry ? skel->progs.mid_release_direct_fentry :
			skel->progs.mid_release_direct_kprobe;
	} else {
		release_prog = can_attach_fentry ? skel->progs.mid_release_kref_fentry :
			skel->progs.mid_release_kref_kprobe;
	}
	pr_info("Attaching to %s with %s (%s)\n", release_func,
		can_attach_fentry ? "fentry" : "kprobe",
		release_mid_params == 2 ? "server, mid" :
		single_direct_release ? "struct mid_q_entry *" : "struct kref *");
	bpf_program__set_autoload(release_prog, true);
	bpf_program__set_autoattach(release_prog, true);

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