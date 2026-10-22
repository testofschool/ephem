#ifndef EPHEM_WORKER_CONTAINMENT_H
#define EPHEM_WORKER_CONTAINMENT_H

/* Installs the terminal classic seccomp-BPF policy. The returned descriptor
 * receives execve notifications; every other unlisted syscall kills the task.
 * The sole bootstrap sendmsg is restricted to control_fd, which is closed
 * before untrusted code executes. */
int ephem_install_seccomp(int control_fd);

#endif
