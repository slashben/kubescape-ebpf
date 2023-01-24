// +build ignore

#include "common.h"
#include <linux/limits.h> 
//#include <asm/ptrace.h>
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	int syscall_nr;
	u8 comm[16];
	u32 pid;
	u32 ppid;
	u32 dirfd;
	u8 path[PATH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct syscalls_enter_open_args
{
    unsigned long long unused;
    long syscall_nr;
    long filename_ptr;
    long flags;
    long mode;
};
struct syscalls_exit_open_args
{
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

struct syscalls_enter_openat_args
{
    unsigned long long unused;
    long syscall_nr;
	long dirfd;
    long filename_ptr;
    long flags;
    long mode;
};
struct syscalls_exit_openat_args
{
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_openat_args *ctx) {
//int BPF_PROG(tracepoint_enter_openat,int dirfd, char *pathname, int flags, int mode) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->syscall_nr = ctx->syscall_nr;
	task_info->pid = tgid;
	task_info->dirfd = ctx->dirfd;
	task_info->ppid = 0; 

	bpf_probe_read_user_str(task_info->path, sizeof(task_info->path),(char*)ctx->filename_ptr);

	bpf_get_current_comm(&task_info->comm, 16);
	task_info->comm[15] = 0;


	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx) {
//int BPF_PROG(tracepoint_enter_openat,int dirfd, char *pathname, int flags, int mode) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	task_info->syscall_nr = ctx->syscall_nr;
	task_info->pid = tgid;
	task_info->dirfd = 0;
	task_info->ppid = 0; 

	bpf_probe_read_user_str(task_info->path, sizeof(task_info->path),(char*)ctx->filename_ptr);
	
	bpf_get_current_comm(&task_info->comm, 16);
	task_info->comm[15] = 0;

	bpf_ringbuf_submit(task_info, 0);

	return 0;
}