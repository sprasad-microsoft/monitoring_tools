#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

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

int get_func_param_count(const char *name, const char *mod)
{
	struct btf *btf, *vmlinux_btf, *module_btf = NULL;
	const struct btf_type *func, *proto;
	int err, id, btf_fd = -1;

	vmlinux_btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux_btf);
	if (err)
		return err;

	btf = vmlinux_btf;
	if (mod) {
		btf_fd = get_module_btf(mod, vmlinux_btf, &module_btf);
		if (btf_fd < 0) {
			err = -EINVAL;
			goto cleanup;
		}
		btf = module_btf;
	}

	id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (id <= 0) {
		err = id < 0 ? id : -ENOENT;
		goto cleanup;
	}
	func = btf__type_by_id(btf, id);
	proto = func ? btf__type_by_id(btf, func->type) : NULL;
	err = proto && btf_is_func_proto(proto) ? btf_vlen(proto) : -EINVAL;

cleanup:
	if (btf_fd >= 0)
		close(btf_fd);
	btf__free(module_btf);
	btf__free(vmlinux_btf);
	return err;
}