#!/usr/bin/env python3

from bcc import BPF

# Define the data structure for events
program = """
struct data_t {
    int pid;
    char comm[16];
};
BPF_PERF_OUTPUT(events);

int hello(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Process event callback
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid})")

# Load and attach the program
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# Set up perf buffer
b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
