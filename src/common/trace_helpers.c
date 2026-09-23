#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <string.h>
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

bool kernel_function_exists(const char *name)
{
	char symbol[256];
	char type;
	FILE *file;
	bool found = false;

	file = fopen("/proc/kallsyms", "r");
	if (!file)
		return false;
	while (fscanf(file, "%*s %c %255s", &type, symbol) == 2) {
		if (!strcmp(symbol, name)) {
			found = true;
			break;
		}
	}
	fclose(file);
	return found;
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

/*
 * BTF presence and a matching function prototype do not prove that fentry is
 * usable. In particular, supported SLES kernels expose the relevant BTF but
 * reject tracing programs when the verifier cannot validate the complete
 * argument context. A minimal program that returns immediately can therefore
 * produce a false positive.
 *
 * Load and attach a probe that reads every argument slot described by BTF.
 * This exercises the same context boundary needed by the real program. On
 * rejection, callers select the kprobe fallback instead of attempting an
 * fentry program that will fail during the final skeleton load.
 */
static bool fentry_try_attach(int id, int btf_fd, int parameter_count)
{
	int prog_fd, attach_fd;
	char error[4096];
	struct bpf_insn insns[14] = {};
	int instruction_count = 0;
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
			.expected_attach_type = BPF_TRACE_FENTRY,
			.attach_btf_id = id,
			.attach_btf_obj_fd = btf_fd,
			.log_buf = error,
			.log_size = sizeof(error),
	);
		int index;

		if (parameter_count < 0 || parameter_count > 12)
			return false;
		for (index = 0; index < parameter_count; index++) {
			insns[instruction_count++] = (struct bpf_insn) {
				.code = BPF_LDX | BPF_MEM | BPF_DW,
				.dst_reg = BPF_REG_0,
				.src_reg = BPF_REG_1,
				.off = index * sizeof(__u64),
			};
		}
		insns[instruction_count++] = (struct bpf_insn) {
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		};
		insns[instruction_count++] = (struct bpf_insn) {
			.code = BPF_JMP | BPF_EXIT,
		};

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
				instruction_count, &opts);
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
	const struct btf_type *func, *proto;
	bool result = false;
	int err, id, parameter_count, btf_fd = 0;

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
	func = btf__type_by_id(btf, id);
	proto = func ? btf__type_by_id(btf, func->type) : NULL;
	if (!proto || !btf_is_func_proto(proto))
		goto cleanup;
	parameter_count = btf_vlen(proto);

	result = fentry_try_attach(id, btf_fd, parameter_count);

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