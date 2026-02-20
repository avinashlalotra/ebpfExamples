
all: vmlinux
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c main.c -o prog.bpf.o

load:
	sudo bpftool prog load prog.bpf.o /sys/fs/bpf/myprog autoattach

vmlinux:
	echo "[+] Dumping vmlinux BTF for CO-RE"
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

unload:
	sudo rm /sys/fs/bpf/myprog

showlog:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f prog.bpf.o

