OUTPUT := src/.output
BINOUT := src/bin
CLANG ?= clang
BPFTOOL ?= bpftool
Q = @
msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory

# only x86 for now
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

VMLINUX := src/common/$(ARCH)/vmlinux.h
VMLINUXCIFS := src/common/$(ARCH)/cifs_btf.h

INCLUDES := -Isrc/common/$(ARCH) -Isrc/common -I$(OUTPUT)
CFLAGS := -g -Wall
# Static-link libbpf + zlib, Dynamic-link libelf + libc/librt
LIBS := -Wl,-Bstatic -l:libbpf.a -lz -Wl,-Bdynamic -lelf -lrt

# Clang system includes for BPF target
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Discover sources
BPF_SRCS := $(wildcard src/bpf/*.bpf.c)
BPF_OBJS := $(patsubst src/bpf/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SRCS))

COMMON_SRCS := $(wildcard src/*.c)

USER_SRCS := $(wildcard src/user/*.c)
USER_BINS := $(patsubst src/user/%.c,$(BINOUT)/%,$(USER_SRCS))

.PHONY: all
all: $(USER_BINS) $(BINOUT)/libringbuf_shim.so

# Allow building individual targets by short name (e.g., make minimal)
APPS := $(notdir $(USER_BINS))
.PHONY: $(APPS)
$(APPS): %: $(BINOUT)/%

.PHONY: clean
clean:
	$(call msg,CLEAN,$(OUTPUT) $(BINOUT))
	$(Q)rm -rf $(OUTPUT) $(BINOUT)/*

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(BINOUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# 1) Compile BPF programs
$(OUTPUT)/%.bpf.o: src/bpf/%.bpf.c $(VMLINUX) $(VMLINUXCIFS) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -Wno-missing-declarations \
		-c $< -o $@

# 2) Generate skeleton headers
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# 3) Build userspace binaries (each .c expects a matching .skel.h)
$(BINOUT)/%: src/user/%.c $(OUTPUT)/%.skel.h $(COMMON_SRCS) | $(BINOUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $< $(COMMON_SRCS) -o $@ $(LIBS)

# 4) Build ring buffer shim shared library (consumed by Python via ctypes)
$(BINOUT)/libringbuf_shim.so: src/ringbuf_shim.c | $(BINOUT)
	$(call msg,SO,$@)
	$(Q)$(CC) -fPIC -shared -g -Wall $(INCLUDES) $< -o $@ -lbpf

# Keep intermediate files (.bpf.o, .skel.h)
.SECONDARY:

# delete failed targets
.DELETE_ON_ERROR: