// SPDX-License-Identifier: GPL-2.0
/* Privileged, dedicated-Linux self-test and example of all-or-nothing LSM
 * attachment. It enrolls only itself and its short-lived test descendants. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "warm_containment.h"

static int active_lsm(void)
{
    char line[4096];
    FILE *file = fopen("/sys/kernel/security/lsm", "r");
    char *item;
    int found = 0;
    if (!file)
        return 0;
    if (fgets(line, sizeof(line), file)) {
        for (item = strtok(line, ",\n"); item; item = strtok(NULL, ",\n")) {
            if (!strcmp(item, "bpf"))
                found = 1;
        }
    }
    fclose(file);
    return found;
}

static int denied(long result)
{
    return result == -1 && errno == EPERM;
}

static int clean_exit(pid_t child)
{
    int status;
    pid_t result;
    do {
        result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int read_probe(int ipc, char *byte)
{
    struct pollfd probe = { .fd = ipc, .events = POLLIN };
    int ready;
    do {
        ready = poll(&probe, 1, 2000);
    } while (ready < 0 && errno == EINTR);
    return ready == 1 && (probe.revents & POLLIN) && read(ipc, byte, 1) == 1;
}

static int attack_probes(int ipc, int internet, int executable)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    char *const argv[] = { "/bin/true", NULL };
    char *const envp[] = { NULL };
    pid_t grandchild;
    char byte = 'a';
    if (!denied(socket(AF_INET, SOCK_STREAM, 0)) ||
        !denied(socket(AF_INET6, SOCK_STREAM, 0)) ||
        !denied(socket(AF_UNIX, SOCK_STREAM, 0)))
        return 1;
    if (!denied(connect(internet, (void *)&address, sizeof(address))) ||
        !denied(sendto(internet, &byte, 1, 0, (void *)&address, sizeof(address))))
        return 2;
    if (!denied(execve("/bin/true", argv, envp)) ||
        !denied(syscall(SYS_execveat, executable, "", argv, envp, AT_EMPTY_PATH)))
        return 3;
    grandchild = fork();
    if (grandchild < 0)
        return 4;
    if (!grandchild)
        _exit(denied(socket(AF_INET, SOCK_DGRAM, 0)) ? 0 : 5);
    if (!clean_exit(grandchild))
        return 6;
    /* Existing local gate stream remains usable after every denied attempt. */
    if (write(ipc, &byte, 1) != 1)
        return 7;
    return 0;
}

static int set_generation(int tasks, int generations, int pidfd, __u64 id,
                          __u64 task_flags)
{
    struct ephem_warm_generation generation = {0};
    struct ephem_warm_task baseline = {
        .generation = id,
        .kind = EPHEM_WARM_BASELINE,
        .depth = 0,
    };
    if (bpf_map_update_elem(generations, &id, &generation, BPF_NOEXIST))
        return -1;
    if (bpf_map_update_elem(tasks, &pidfd, &baseline, task_flags)) {
        int saved = errno;
        bpf_map_delete_elem(generations, &id);
        errno = saved;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_link *links[32] = {0};
    struct ephem_warm_generation generation;
    struct rlimit memlock = { RLIM_INFINITY, RLIM_INFINITY };
    int links_count = 0;
    int tasks = -1, generations = -1, pidfd = -1;
    int ipc[2] = {-1, -1}, internet = -1, executable = -1;
    __u64 generation_id = 1;
    int enrolled = 0;
    int result = 1;
    pid_t child;
    char byte;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /absolute/path/warm_containment.bpf.o\n", argv[0]);
        return 2;
    }
    if (geteuid() != 0 || !active_lsm()) {
        fprintf(stderr, "UNRUN: requires root and active bpf in /sys/kernel/security/lsm\n");
        return 77;
    }
    /* Modern kernels account BPF memory through memcg; older ones need this. */
    if (setrlimit(RLIMIT_MEMLOCK, &memlock) && errno != EPERM) {
        perror("setrlimit");
        return 1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc) ||
        (internet = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0 ||
        (executable = open("/bin/true", O_RDONLY | O_CLOEXEC)) < 0) {
        perror("open probe descriptors");
        goto out;
    }
    object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) {
        object = NULL;
        fprintf(stderr, "BPF object open failed\n");
        goto out;
    }
    if (bpf_object__load(object)) {
        fprintf(stderr, "BPF verifier/load failed; no enrollment performed\n");
        goto out;
    }
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link;
        if (links_count == (int)(sizeof(links) / sizeof(links[0]))) {
            fprintf(stderr, "too many LSM programs\n");
            goto out;
        }
        link = bpf_program__attach_lsm(program);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "LSM attach failed; no enrollment performed\n");
            goto out;
        }
        links[links_count++] = link;
    }
    tasks = bpf_object__find_map_fd_by_name(object, "warm_tasks");
    generations = bpf_object__find_map_fd_by_name(object, "warm_generations");
    pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (tasks < 0 || generations < 0 || pidfd < 0 ||
        set_generation(tasks, generations, pidfd, generation_id, BPF_NOEXIST)) {
        perror("enroll baseline by pidfd");
        goto out;
    }
    enrolled = 1;
    child = fork();
    if (child < 0) {
        perror("fork first generation");
        goto out;
    }
    if (!child)
        _exit(attack_probes(ipc[1], internet, executable));
    if (!clean_exit(child)) {
        fprintf(stderr, "worker or inherited grandchild probe failed\n");
        goto out;
    }
    if (!read_probe(ipc[0], &byte) ||
        bpf_map_lookup_elem(generations, &generation_id, &generation) ||
        (generation.violations & (EPHEM_WARM_DENIED_EXEC | EPHEM_WARM_DENIED_NETWORK)) !=
            (EPHEM_WARM_DENIED_EXEC | EPHEM_WARM_DENIED_NETWORK)) {
        fprintf(stderr, "violation ledger or existing local stream failed\n");
        goto out;
    }
    /* A fresh id demonstrates request isolation; never clear an active id. */
    generation_id = 2;
    if (set_generation(tasks, generations, pidfd, generation_id, BPF_EXIST)) {
        perror("advance baseline generation");
        goto out;
    }
    child = fork();
    if (child < 0) {
        perror("fork clean generation");
        goto out;
    }
    if (!child)
        _exit(write(ipc[1], "b", 1) == 1 ? 0 : 8);
    if (!clean_exit(child) || !read_probe(ipc[0], &byte) ||
        bpf_map_lookup_elem(generations, &generation_id, &generation) ||
        generation.violations != 0) {
        fprintf(stderr, "fresh clean generation was not isolated\n");
        goto out;
    }
    printf("PASS: execve/execveat, IPv4/IPv6/UNIX creation, inherited IPv4 use, "
           "fork inheritance, local IPC, shared violation ledger, fresh generation\n");
    result = 0;
out:
    /* Every child is reaped before label removal or link destruction. */
    if (enrolled && bpf_map_delete_elem(tasks, &pidfd)) {
        perror("remove baseline enrollment");
        result = 1;
    }
    if (pidfd >= 0)
        close(pidfd);
    if (ipc[0] >= 0)
        close(ipc[0]);
    if (ipc[1] >= 0)
        close(ipc[1]);
    if (internet >= 0)
        close(internet);
    if (executable >= 0)
        close(executable);
    while (links_count)
        bpf_link__destroy(links[--links_count]);
    bpf_object__close(object);
    return result;
}
