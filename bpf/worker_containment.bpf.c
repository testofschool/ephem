#define _GNU_SOURCE
#include "worker_containment.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EPHEM_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define EPHEM_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "ephem-jail supports Linux x86_64 and aarch64 only"
#endif

#define ALLOW_NR(name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

int ephem_install_seccomp(int control_fd)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EPHEM_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        /* x32 syscall numbers never match the native allowlist. */
        ALLOW_NR(read),
        ALLOW_NR(write),
        ALLOW_NR(readv),
        ALLOW_NR(writev),
        ALLOW_NR(pread64),
        ALLOW_NR(close),
        ALLOW_NR(lseek),
        ALLOW_NR(fstat),
        ALLOW_NR(newfstatat),
#ifdef __NR_stat
        ALLOW_NR(stat),
#endif
#ifdef __NR_lstat
        ALLOW_NR(lstat),
#endif
        ALLOW_NR(statx),
        ALLOW_NR(openat),
#ifdef __NR_open
        ALLOW_NR(open),
#endif
#ifdef __NR_access
        ALLOW_NR(access),
#endif
        ALLOW_NR(faccessat),
        ALLOW_NR(faccessat2),
        ALLOW_NR(readlinkat),
#ifdef __NR_readlink
        ALLOW_NR(readlink),
#endif
        ALLOW_NR(getdents64),
        ALLOW_NR(getcwd),
        ALLOW_NR(chdir),
        ALLOW_NR(fchdir),
        ALLOW_NR(dup),
        ALLOW_NR(dup3),
#ifdef __NR_dup2
        ALLOW_NR(dup2),
#endif
        ALLOW_NR(fcntl),
        ALLOW_NR(mmap),
        ALLOW_NR(mprotect),
        ALLOW_NR(munmap),
        ALLOW_NR(mremap),
        ALLOW_NR(madvise),
        ALLOW_NR(brk),
        ALLOW_NR(rt_sigaction),
        ALLOW_NR(rt_sigprocmask),
        ALLOW_NR(rt_sigreturn),
        ALLOW_NR(sigaltstack),
        ALLOW_NR(futex),
        ALLOW_NR(set_tid_address),
        ALLOW_NR(set_robust_list),
        ALLOW_NR(rseq),
#ifdef __NR_arch_prctl
        ALLOW_NR(arch_prctl),
#endif
        ALLOW_NR(clock_gettime),
        ALLOW_NR(clock_nanosleep),
        ALLOW_NR(nanosleep),
        ALLOW_NR(gettimeofday),
        ALLOW_NR(times),
        ALLOW_NR(getrusage),
        ALLOW_NR(sched_yield),
        ALLOW_NR(sched_getaffinity),
        ALLOW_NR(getpid),
        ALLOW_NR(getppid),
        ALLOW_NR(gettid),
        ALLOW_NR(getuid),
        ALLOW_NR(geteuid),
        ALLOW_NR(getgid),
        ALLOW_NR(getegid),
        ALLOW_NR(getresuid),
        ALLOW_NR(getresgid),
        ALLOW_NR(getgroups),
        ALLOW_NR(capget),
        ALLOW_NR(uname),
        ALLOW_NR(getrandom),
#ifdef __NR_getrlimit
        ALLOW_NR(getrlimit),
#endif
        ALLOW_NR(prlimit64),
        ALLOW_NR(ppoll),
        ALLOW_NR(pselect6),
#ifdef __NR_poll
        ALLOW_NR(poll),
#endif
#ifdef __NR_select
        ALLOW_NR(select),
#endif
        ALLOW_NR(umask),
        /* Only regular files/directories may be created, under Landlock's
         * /tmp rule. The entire remaining root mount is recursively read-only. */
        ALLOW_NR(mkdirat),
#ifdef __NR_mkdir
        ALLOW_NR(mkdir),
#endif
        ALLOW_NR(unlinkat),
#ifdef __NR_unlink
        ALLOW_NR(unlink),
#endif
#ifdef __NR_rmdir
        ALLOW_NR(rmdir),
#endif
        ALLOW_NR(renameat),
        ALLOW_NR(renameat2),
#ifdef __NR_rename
        ALLOW_NR(rename),
#endif
        ALLOW_NR(ftruncate),
        ALLOW_NR(truncate),
        ALLOW_NR(fchmod),
        ALLOW_NR(fchmodat),
        ALLOW_NR(fsync),
        ALLOW_NR(fdatasync),
        ALLOW_NR(exit),
        ALLOW_NR(exit_group),
        /* PHP-CGI probes whether stdin is a FastCGI socket. The launcher
         * enforces pipe stdin/stdout, closes every other inherited descriptor
         * and forbids all socket creation. Return the correct non-socket
         * failure without executing a network syscall or inspecting pointers. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOTSOCK),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* PHP's optional Zend anonymous-VMA label ignores the return value.
         * Emulate an older kernel's EINVAL for exactly this metadata probe;
         * execute no prctl and inspect no worker address/string. All other
         * prctl requests, including dumpability/filter changes, remain fatal. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 8),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, UINT32_C(0x53564d41), 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[1]) + 4U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EINVAL),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* Read-only terminal/pipe queries used by language startup. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 8),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCGWINSZ, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONREAD, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* A broker permits exactly the bootstrap execve. It kills every
         * subsequent execve notification. execveat is never permitted. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        /* Pass the listener to the supervisor before exec, then close this
         * socket. No socket/socketpair/connect/recvmsg syscall is allowed. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)control_fd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
}
