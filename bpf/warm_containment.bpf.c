// SPDX-License-Identifier: GPL-2.0
/* Optional system-wide BPF LSM. Default runtime enforcement is the separate
 * child-installed seccomp policy; merely building this file enforces nothing.
 *
 * A trusted loader enrolls a quiescent, single-threaded warm baseline through
 * a pidfd in warm_tasks. The baseline never executes request code. task_alloc
 * labels each fork before it can run. Local task storage is freed by the
 * kernel, so PID reuse cannot transfer a label to an unrelated task.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "warm_containment.h"

/* CO-RE needs only these fields; their offsets are resolved against target BTF.
 * No distribution-specific generated vmlinux.h is checked into the tree. */
struct task_struct;
struct linux_binprm;
struct sockaddr;
struct msghdr;
struct file;
struct sock_common {
    unsigned short skc_family;
} __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));
struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

#define EPHEM_EPERM 1
#define EPHEM_ENOMEM 12
#define EPHEM_AF_UNIX 1

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); /* userspace supplies pidfd, never a numeric PID */
    __type(value, struct ephem_warm_task);
} warm_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ephem_warm_generation);
} warm_generations SEC(".maps");

static __always_inline struct ephem_warm_task *current_label(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    return bpf_task_storage_get(&warm_tasks, task, 0, 0);
}

static __always_inline int is_worker(void)
{
    struct ephem_warm_task *task = current_label();
    return task && task->kind == EPHEM_WARM_WORKER;
}

static __always_inline int deny_worker(__u32 reason)
{
    struct ephem_warm_task *task = current_label();
    struct ephem_warm_generation *generation;

    if (!task || task->kind != EPHEM_WARM_WORKER)
        return 0;
    generation = bpf_map_lookup_elem(&warm_generations, &task->generation);
    if (generation)
        __sync_fetch_and_or(&generation->violations, reason);
    /* Missing generation state must never turn a labeled worker into allow. */
    return -EPHEM_EPERM;
}

static __always_inline int deny_preserving(int previous, __u32 reason)
{
    int denied = deny_worker(reason);
    return previous ? previous : denied;
}

SEC("lsm/task_alloc")
int BPF_PROG(warm_inherit, struct task_struct *child,
             unsigned long clone_flags, int ret)
{
    struct ephem_warm_task *parent;
    struct ephem_warm_task inherited;
    struct ephem_warm_generation *generation;

    if (ret) {
        deny_worker(EPHEM_WARM_DENIED_FORK);
        return ret;
    }
    parent = current_label();
    if (!parent)
        return 0;
    generation = bpf_map_lookup_elem(&warm_generations, &parent->generation);
    if (!generation)
        return -EPHEM_EPERM;
    if (parent->depth == (__u32)-1) {
        __sync_fetch_and_or(&generation->violations, EPHEM_WARM_DENIED_FORK);
        return -EPHEM_EPERM;
    }
    inherited.generation = parent->generation;
    inherited.kind = EPHEM_WARM_WORKER;
    inherited.depth = parent->depth + 1;
    if (!bpf_task_storage_get(&warm_tasks, child, &inherited,
                              BPF_LOCAL_STORAGE_GET_F_CREATE)) {
        __sync_fetch_and_or(&generation->violations, EPHEM_WARM_DENIED_FORK);
        return -EPHEM_ENOMEM;
    }
    return 0;
}

/* bprm_check_security covers both execve and execveat, including interpreters. */
SEC("lsm/bprm_check_security")
int BPF_PROG(warm_exec, struct linux_binprm *bprm, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_EXEC);
}

/* Every new socket is forbidden. Only preconnected AF_UNIX gate descriptors
 * may be inherited. In particular AF_INET/AF_INET6 are denied, never redirected:
 * LSM return values cannot rewrite sockaddr arguments or redirect a socket. */
SEC("lsm/socket_create")
int BPF_PROG(warm_socket_create, int family, int type, int protocol,
             int kern, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK);
}

SEC("lsm/socket_connect")
int BPF_PROG(warm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK);
}

SEC("lsm/socket_bind")
int BPF_PROG(warm_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK);
}

SEC("lsm/socket_listen")
int BPF_PROG(warm_socket_listen, struct socket *sock, int backlog, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK);
}

SEC("lsm/socket_accept")
int BPF_PROG(warm_socket_accept, struct socket *sock,
             struct socket *newsock, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK);
}

static __always_inline int check_socket(struct socket *sock)
{
    if (!is_worker())
        return 0;
    /* Null/unreadable socket fields are fail-closed, not AF_UNIX. */
    if (BPF_CORE_READ(sock, sk, __sk_common.skc_family) != EPHEM_AF_UNIX)
        return deny_worker(EPHEM_WARM_DENIED_NETWORK);
    return 0;
}

/* Block use of mistakenly inherited INET sockets as well as new creation.
 * send/recv hooks are also reached by socket read/write kernel paths. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(warm_socket_sendmsg, struct socket *sock,
             struct msghdr *msg, int size, int ret)
{
    return ret ? deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK) : check_socket(sock);
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(warm_socket_recvmsg, struct socket *sock, struct msghdr *msg,
             int size, int flags, int ret)
{
    return ret ? deny_preserving(ret, EPHEM_WARM_DENIED_NETWORK) : check_socket(sock);
}

/* Do not permit SCM_RIGHTS to import an unreviewed descriptor over gate IPC. */
SEC("lsm/file_receive")
int BPF_PROG(warm_file_receive, struct file *file, int ret)
{
    return deny_preserving(ret, EPHEM_WARM_DENIED_FD);
}

char LICENSE[] SEC("license") = "GPL";
