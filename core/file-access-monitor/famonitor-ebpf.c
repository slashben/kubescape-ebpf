//go:build exclude
#include <vmlinux.h>
//#include "common.h"
#include <linux/limits.h> 
#include <bpf_helpers.h>
#include <bpf_core_read.h>
//#include <asm/ptrace.h>
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	long timestamp;
	u64 mntns_id;
	int syscall_nr;
	u8 comm[16];
	u32 pid;
	u32 ppid;
	u64 cgroupid;
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

struct syscalls_enter_execve_args
{
    unsigned long long unused;
    long syscall_nr;
    const char* file_name;
    const char* const* argv;
	const char* const* envp;
};

void add_common_event_info(struct event *task_info) {
	struct task_struct *task;	
	task = (struct task_struct*) bpf_get_current_task();

	task_info->timestamp = bpf_ktime_get_ns();
	task_info->mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	task_info->pid = bpf_get_current_pid_tgid() >> 32;
	task_info->ppid = 0; 
	task_info->cgroupid = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&task_info->comm, 16);
	task_info->comm[15] = 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_openat_args *ctx) {
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	// Common data
	add_common_event_info(task_info);

	// Call specific
	task_info->syscall_nr = ctx->syscall_nr;
	bpf_probe_read_user_str(task_info->path, sizeof(task_info->path),(char*)ctx->filename_ptr);

	// Submit to ring buffer
	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx) {
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	// Common data
	add_common_event_info(task_info);

	// Call specific
	task_info->syscall_nr = ctx->syscall_nr;
	bpf_probe_read_user_str(task_info->path, sizeof(task_info->path),(char*)ctx->filename_ptr);

	// Submit
	bpf_ringbuf_submit(task_info, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscalls_enter_execve_args *ctx) {
	struct event *task_info;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	// Common data
	add_common_event_info(task_info);

	// Call specific
	task_info->syscall_nr = ctx->syscall_nr;
	bpf_probe_read_user_str(task_info->path, sizeof(task_info->path),(char*)ctx->file_name);

	// Submit
	bpf_ringbuf_submit(task_info, 0);

	return 0;
}