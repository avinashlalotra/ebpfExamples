BPF_INCLUDE_DIR := ../../include/bpf
INCLUDE_DIR := ../../include
USER_INCLUDE_DIR := ../../include/user
BPF_OBJ_NAME := fentry_bpf

# ---- Expect configs from parent ----
ifndef CONFIG_CREATE
$(error CONFIG_CREATE not set by parent Makefile)
endif

ifndef CONFIG_DELETE
$(error CONFIG_DELETE not set by parent Makefile)
endif

ifndef CONFIG_MODIFY
$(error CONFIG_MODIFY not set by parent Makefile)
endif

ifndef CONFIG_RENAME
$(error CONFIG_RENAME not set by parent Makefile)
endif



# ---- Base source files (always built) ----
BPF_SRCS := maps.bpf.c

# ---- Conditionally add feature files ----
ifeq ($(CONFIG_CREATE),y)
BPF_SRCS += create.bpf.c
endif

ifeq ($(CONFIG_DELETE),y)
BPF_SRCS += delete.bpf.c
endif

ifeq ($(CONFIG_MODIFY),y)
BPF_SRCS += modify.bpf.c
endif

ifeq ($(CONFIG_RENAME),y)
BPF_SRCS += rename.bpf.c
endif



# ---- Objects ----
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# ---- Compiler flags ----
BPF_CFLAGS := -g -O2 -target bpf -mcpu=v3 \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(BPF_INCLUDE_DIR) -I$(INCLUDE_DIR)

ifeq ($(CONFIG_CREATE),y)
BPF_CFLAGS += -DCONFIG_CREATE
endif

ifeq ($(CONFIG_DELETE),y)
BPF_CFLAGS += -DCONFIG_DELETE
endif

ifeq ($(CONFIG_MODIFY),y)
BPF_CFLAGS += -DCONFIG_MODIFY
endif

ifeq ($(CONFIG_RENAME),y)
BPF_CFLAGS += -DCONFIG_RENAME
endif


BPF_CFLAGS += -DCONFIG_BPF

# ---- Targets ----
all: SKEL_BUILD

%.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@

BPF_BUILD: $(BPF_OBJS)
	bpftool gen object $(BPF_OBJ_NAME) $(BPF_OBJS)

SKEL_BUILD: vmlinux BPF_BUILD
	bpftool gen skeleton $(BPF_OBJ_NAME) > $(USER_INCLUDE_DIR)/$(BPF_OBJ_NAME).skel.h

vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_INCLUDE_DIR)/vmlinux.h

clean:
	rm -f *.bpf.o
	rm -f $(BPF_OBJ_NAME)
	rm -f $(USER_INCLUDE_DIR)/$(BPF_OBJ_NAME).skel.h
	rm -f $(BPF_INCLUDE_DIR)/vmlinux.h