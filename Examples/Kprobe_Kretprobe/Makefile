all: vmlinux
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c main.c -o prog.bpf.o

load:
	sudo bpftool prog loadall prog.bpf.o /sys/fs/bpf/my_kprobe_prog autoattach

vmlinux:
	echo "[+] Dumping vmlinux BTF for CO-RE"
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

unload:
	sudo rm -rf /sys/fs/bpf/my_kprobe_prog || true

showlog:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

showmap:
	# Show BPF maps loaded to the system and dump the contents of the newly populated maps
	sudo bpftool map
	@echo "Try running: sudo bpftool map dump id <map_id>"

clean:
	rm -f prog.bpf.o vmlinux.h
