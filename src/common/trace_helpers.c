#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <string.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <unistd.h>

bool tracepoint_exists(const char *category, const char *name)
{
	char path[256];

	if (snprintf(path, sizeof(path),
		     "/sys/kernel/tracing/events/%s/%s/id",
		     category, name) >= sizeof(path))
		return false;
	if (access(path, R_OK) == 0)
		return true;

	if (snprintf(path, sizeof(path),
		     "/sys/kernel/debug/tracing/events/%s/%s/id",
		     category, name) >= sizeof(path))
		return false;
	return access(path, R_OK) == 0;
}

static int get_module_btf(const char *mod, struct btf *vmlinux_btf,
			  struct btf **module_btf)
{
	struct bpf_btf_info info;
	char name[64];
	__u32 id = 0, len;
	int fd, err;

	while (!bpf_btf_get_next_id(id, &id)) {
		memset(&info, 0, sizeof(info));
		memset(name, 0, sizeof(name));
		info.name = (__u64)(unsigned long)name;
		info.name_len = sizeof(name);
		len = sizeof(info);

		fd = bpf_btf_get_fd_by_id(id);
		if (fd < 0)
			continue;
		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		if (!err && !strcmp(name, mod)) {
			*module_btf = btf__load_module_btf(mod, vmlinux_btf);
			if (libbpf_get_error(*module_btf)) {
				*module_btf = NULL;
				close(fd);
				return -1;
			}
			return fd;
		}
		close(fd);
	}
	return -1;
}

static bool fentry_try_attach(int id, int btf_fd)
{
	int prog_fd, attach_fd;
	char error[4096];
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
			.expected_attach_type = BPF_TRACE_FENTRY,
			.attach_btf_id = id,
			.attach_btf_obj_fd = btf_fd,
			.log_buf = error,
			.log_size = sizeof(error),
	);

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
			sizeof(insns) / sizeof(struct bpf_insn), &opts);
	if (prog_fd < 0)
		return false;

	attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
	if (attach_fd >= 0)
		close(attach_fd);

	close(prog_fd);
	return attach_fd >= 0;
}

bool fentry_can_attach(const char *name, const char *mod)
{
	struct btf *btf, *vmlinux_btf, *module_btf = NULL;
	bool result = false;
	int err, id, btf_fd = 0;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
		return false;

	btf = vmlinux_btf;

	if (mod) {
		btf_fd = get_module_btf(mod, vmlinux_btf, &module_btf);
		if (btf_fd < 0)
			goto cleanup;
		btf = module_btf;
	}

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (id <= 0)
		goto cleanup;

	result = fentry_try_attach(id, btf_fd);

cleanup:
	if (btf_fd > 0)
		close(btf_fd);
	btf__free(module_btf);
	btf__free(vmlinux_btf);
	return result;
}

static bool kernel_version_ge(int major, int minor)
{
	struct utsname buf;
	int kmajor, kminor;

	if (uname(&buf) != 0)
		return false;
	if (sscanf(buf.release, "%d.%d", &kmajor, &kminor) != 2)
		return false;
	return kmajor > major || (kmajor == major && kminor >= minor);
}

int get_func_param_count(const char *name, const char *mod)
{
	/*
	 * __release_mid signature changed in 6.19, but went to 7.0 stable:
	 *   pre-6.19: __release_mid(struct kref *kref)         — 1 param
	 *   6.19+:    __release_mid(server, mid)               — 2 params
	 */
	(void)name;
	(void)mod;
	return kernel_version_ge(6, 19) ? 2 : 1;
}