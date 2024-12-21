#!/usr/bin/env python3

from bcc import BPF

# Define the BPF program
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

# Load and compile the BPF program
b = BPF(text=program)

# Attach the program to execve syscall
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# Print trace output
b.trace_print()