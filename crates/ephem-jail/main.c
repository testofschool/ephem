#define _GNU_SOURCE
#include "worker_containment.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CONTROL_FD 3
#define PARENT_FD 4
#define SETUP_MAGIC UINT32_C(0x45504832)

struct setup_message {
    uint32_t magic;
    uint32_t landlock_abi;
    int32_t error_number;
};

static volatile sig_atomic_t interrupted;

static void catch_signal(int number)
{
    interrupted = number;
}

static int kill_worker(int pidfd)
{
    return (int)syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
}

static int send_setup(int fd, const struct setup_message *setup, int listener)
{
    struct iovec iov = {.iov_base = (void *)setup, .iov_len = sizeof(*setup)};
    char ancillary[CMSG_SPACE(sizeof(int))];
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    memset(ancillary, 0, sizeof(ancillary));
    if (listener >= 0) {
        message.msg_control = ancillary;
        message.msg_controllen = sizeof(ancillary);
        struct cmsghdr *control = CMSG_FIRSTHDR(&message);
        control->cmsg_level = SOL_SOCKET;
        control->cmsg_type = SCM_RIGHTS;
        control->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(control), &listener, sizeof(listener));
    }
    return sendmsg(fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(*setup) ? 0 : -1;
}

static void child_failure(int error_number)
{
    struct setup_message setup = {
        .magic = SETUP_MAGIC, .landlock_abi = 0,
        .error_number = error_number > 0 ? error_number : EIO,
    };
    (void)send_setup(CONTROL_FD, &setup, -1);
    _exit(125);
}

static void require_success(int result)
{
    if (result < 0)
        child_failure(errno);
}

static void check_parent(void)
{
    struct pollfd parent = {.fd = PARENT_FD, .events = POLLIN};
    int result = poll(&parent, 1, 0);
    if (result < 0 || result > 0)
        child_failure(ECHILD);
}

static int apply_landlock(void)
{
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) {
        errno = abi < 0 ? errno : EOPNOTSUPP;
        return -1;
    }
    const uint64_t reads = LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const uint64_t temporary = LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    const uint64_t handled = reads | temporary |
        LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        LANDLOCK_ACCESS_FS_MAKE_SYM;
    struct landlock_ruleset_attr attributes = {.handled_access_fs = handled};
    int ruleset = (int)syscall(SYS_landlock_create_ruleset, &attributes,
                               sizeof(attributes), 0);
    if (ruleset < 0)
        return -1;
    const char *paths[] = {"/", "/tmp"};
    const uint64_t rights[] = {reads, temporary};
    for (size_t index = 0; index < 2; index++) {
        int path = open(paths[index], O_PATH | O_CLOEXEC | O_DIRECTORY);
        if (path < 0) {
            int saved = errno;
            close(ruleset);
            errno = saved;
            return -1;
        }
        struct landlock_path_beneath_attr rule = {
            .allowed_access = rights[index], .parent_fd = path,
        };
        int result = (int)syscall(SYS_landlock_add_rule, ruleset,
                                  LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
        int saved = errno;
        close(path);
        if (result < 0) {
            close(ruleset);
            errno = saved;
            return -1;
        }
    }
    int result = (int)syscall(SYS_landlock_restrict_self, ruleset, 0);
    int saved = errno;
    close(ruleset);
    errno = saved;
    return result < 0 ? -1 : abi;
}

static void limit_resource(int resource, rlim_t value)
{
    struct rlimit limit = {.rlim_cur = value, .rlim_max = value};
    require_success(setrlimit(resource, &limit));
}

static void child_main(const char *root, char **worker_argv,
                       int control, int parent_pidfd)
{
    /* Duplicate first so descriptor-number collisions cannot lose either fd. */
    int saved_control = fcntl(control, F_DUPFD_CLOEXEC, 10);
    if (saved_control < 0)
        _exit(125);
    int saved_parent = fcntl(parent_pidfd, F_DUPFD_CLOEXEC, 10);
    if (saved_parent < 0)
        _exit(125);
    if (dup3(saved_control, CONTROL_FD, O_CLOEXEC) < 0 ||
        dup3(saved_parent, PARENT_FD, O_CLOEXEC) < 0)
        _exit(125);
    require_success((int)syscall(SYS_close_range, 5U, ~0U, 0U));
    require_success(prctl(PR_SET_PDEATHSIG, SIGKILL));
    check_parent();
    int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    require_success(nullfd);
    require_success(dup2(nullfd, STDERR_FILENO));
    close(nullfd);

    require_success(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    require_success(mount(root, root, NULL, MS_BIND | MS_REC, NULL));
    struct mount_attr mount_attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    require_success((int)syscall(SYS_mount_setattr, AT_FDCWD, root,
                                 AT_RECURSIVE, &mount_attributes,
                                 sizeof(mount_attributes)));
    require_success(chdir(root));
    require_success(chroot("."));
    require_success(chdir("/"));
    struct stat temporary;
    if (lstat("/tmp", &temporary) < 0 || !S_ISDIR(temporary.st_mode))
        child_failure(EINVAL);
    require_success(mount("tmpfs", "/tmp", "tmpfs",
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        "size=16777216,nr_inodes=1024,mode=1777"));
    require_success(sethostname("ephem", 5));
    const char *detached[] = {"/proc", "/sys", "/dev"};
    for (size_t index = 0; index < sizeof(detached) / sizeof(detached[0]); index++) {
        if (umount2(detached[index], MNT_DETACH) < 0 &&
            errno != ENOENT && errno != EINVAL)
            child_failure(errno);
    }

    limit_resource(RLIMIT_CORE, 0);
    limit_resource(RLIMIT_NOFILE, 32);
    /* NPROC counts every process with this real UID, including concurrent
     * requests in other PID namespaces. Process/thread creation itself is
     * forbidden by seccomp. Match the gate's maximum in-flight request cap. */
    limit_resource(RLIMIT_NPROC, 128);
    limit_resource(RLIMIT_FSIZE, 16U * 1024U * 1024U);
    limit_resource(RLIMIT_STACK, 8U * 1024U * 1024U);
    limit_resource(RLIMIT_CPU, 30);
    limit_resource(RLIMIT_AS, 256U * 1024U * 1024U);
    umask(0077);
    /* Retain no ambient/inheritable/permitted/effective/bounding capability. */
    require_success(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
    for (int capability = 0; capability <= CAP_LAST_CAP; capability++)
        require_success(prctl(PR_CAPBSET_DROP, capability, 0, 0, 0));
    require_success(setgroups(0, NULL));
    require_success(setresgid(65534, 65534, 65534));
    require_success(setresuid(65534, 65534, 65534));
    struct __user_cap_header_struct capability_header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct capability_data[2] = {{0}, {0}};
    require_success((int)syscall(SYS_capset, &capability_header, capability_data));
    require_success(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    require_success(prctl(PR_SET_DUMPABLE, 0));
    /* Credential changes clear PDEATHSIG; reapply and close its race with a
     * pidfd for the supervisor, whose namespace parent is otherwise invisible. */
    require_success(prctl(PR_SET_PDEATHSIG, SIGKILL));
    check_parent();
    close(PARENT_FD);
    int abi = apply_landlock();
    require_success(abi);

    /* Preserve only the documented CGI variables supplied by the trusted
     * gate. Loader, Python and PHP configuration injection variables disappear. */
    const char *names[] = {"CONTENT_LENGTH", "CONTENT_TYPE", "REQUEST_METHOD",
        "REQUEST_URI", "QUERY_STRING", "SCRIPT_NAME", "SCRIPT_FILENAME",
        "SERVER_PROTOCOL", "GATEWAY_INTERFACE", "SERVER_NAME", "SERVER_PORT"};
    char *values[sizeof(names) / sizeof(names[0])] = {0};
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        const char *value = getenv(names[index]);
        if (value != NULL) {
            values[index] = strdup(value);
            if (values[index] == NULL)
                child_failure(ENOMEM);
        }
    }
    require_success(clearenv());
    require_success(setenv("PATH", "/usr/bin:/bin", 1));
    require_success(setenv("LANG", "C", 1));
    require_success(setenv("HOME", "/tmp", 1));
    require_success(setenv("TMPDIR", "/tmp", 1));
    require_success(setenv("PYTHONDONTWRITEBYTECODE", "1", 1));
    require_success(setenv("REDIRECT_STATUS", "200", 1));
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (values[index] != NULL) {
            require_success(setenv(names[index], values[index], 1));
            free(values[index]);
        }
    }
    int listener = ephem_install_seccomp(CONTROL_FD);
    require_success(listener);
    struct setup_message setup = {
        .magic = SETUP_MAGIC, .landlock_abi = (uint32_t)abi, .error_number = 0,
    };
    if (send_setup(CONTROL_FD, &setup, listener) < 0)
        _exit(125);
    close(listener);
    close(CONTROL_FD);
    /* This single-threaded trusted path is the first execve notification.
     * The supervisor authorizes the bootstrap event, not mutable path bytes.
     * No untrusted instruction executes until that event has completed. */
    execve(worker_argv[0], worker_argv, environ);
    _exit(126);
}

static int receive_setup(int fd, struct setup_message *setup)
{
    char ancillary[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = setup, .iov_len = sizeof(*setup)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary, .msg_controllen = sizeof(ancillary)};
    memset(ancillary, 0, sizeof(ancillary));
    ssize_t count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    if (count != (ssize_t)sizeof(*setup) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
        setup->magic != SETUP_MAGIC || setup->error_number != 0)
        return -1;
    struct cmsghdr *control = CMSG_FIRSTHDR(&message);
    if (control == NULL || control->cmsg_level != SOL_SOCKET ||
        control->cmsg_type != SCM_RIGHTS ||
        control->cmsg_len != CMSG_LEN(sizeof(int)) ||
        CMSG_NXTHDR(&message, control) != NULL)
        return -1;
    int listener = -1;
    memcpy(&listener, CMSG_DATA(control), sizeof(listener));
    return listener;
}

static int supervise(pid_t child, int pidfd, int channel, int *abi)
{
    int listener = -1;
    int exec_count = 0;
    int status = 0;
    struct seccomp_notif_sizes sizes;
    struct seccomp_notif *notification = NULL;
    struct seccomp_notif_resp *response = NULL;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
        goto kill_and_wait;
    notification = calloc(1, sizes.seccomp_notif);
    response = calloc(1, sizes.seccomp_notif_resp);
    if (notification == NULL || response == NULL)
        goto kill_and_wait;
    for (;;) {
        struct pollfd watched[2] = {
            {.fd = pidfd, .events = POLLIN},
            {.fd = listener >= 0 ? listener : channel, .events = POLLIN},
        };
        if (interrupted != 0)
            goto kill_and_wait;
        int result = poll(watched, 2, -1);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            goto kill_and_wait;
        }
        if ((watched[0].revents & POLLIN) != 0)
            break;
        if ((watched[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
            (watched[1].revents & POLLIN) == 0)
            goto kill_and_wait;
        if ((watched[1].revents & POLLIN) == 0)
            continue;
        if (listener < 0) {
            struct setup_message setup;
            listener = receive_setup(channel, &setup);
            if (listener < 0 || setup.landlock_abi < 3)
                goto kill_and_wait;
            *abi = (int)setup.landlock_abi;
            close(channel);
            channel = -1;
            continue;
        }
        memset(notification, 0, sizes.seccomp_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification) < 0) {
            if (errno == EINTR || errno == ENOENT)
                continue;
            goto kill_and_wait;
        }
        if (notification->pid != (uint32_t)child ||
            notification->data.nr != SYS_execve || exec_count != 0)
            goto kill_and_wait;
        memset(response, 0, sizes.seccomp_notif_resp);
        response->id = notification->id;
        response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response) < 0)
            goto kill_and_wait;
        exec_count++;
    }
    goto wait;
kill_and_wait:
    (void)kill_worker(pidfd);
wait:
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            status = 125 << 8;
            break;
        }
    }
    if (listener >= 0)
        close(listener);
    if (channel >= 0)
        close(channel);
    free(notification);
    free(response);
    return status;
}

static int validate_root(const char *root, char resolved[PATH_MAX])
{
    if (root[0] != '/' || realpath(root, resolved) == NULL ||
        strcmp(resolved, "/") == 0)
        return -1;
    /* Require each path component to be root-owned and not group/world
     * writable. This prevents a non-root peer replacing the trusted root. */
    char component[PATH_MAX];
    if (snprintf(component, sizeof(component), "%s", resolved) >=
        (int)sizeof(component))
        return -1;
    for (char *cursor = component + 1;; cursor++) {
        if (*cursor != '/' && *cursor != '\0')
            continue;
        char saved = *cursor;
        *cursor = '\0';
        struct stat info;
        if (lstat(component, &info) < 0 || !S_ISDIR(info.st_mode) ||
            info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            return -1;
        *cursor = saved;
        if (saved == '\0')
            break;
    }
    return 0;
}

/* execve resets dumpability. RLIMIT_CORE=0 does not suppress a piped
 * core_pattern collector, which could persist worker memory outside its jail.
 * Refuse such a host instead of silently changing a host-wide setting. */
static int reject_core_collector(void)
{
    FILE *pattern = fopen("/proc/sys/kernel/core_pattern", "re");
    if (pattern == NULL)
        return -1;
    int first = fgetc(pattern);
    int failed = ferror(pattern) || first == EOF || first == '|';
    fclose(pattern);
    return failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    /* The gate supplies its identity before spawn. Sampling getppid() only
     * after startup could mistakenly adopt init after an early gate death. */
    const char *expected_text = getenv("EPHEM_GATE_PID");
    char *expected_end = NULL;
    errno = 0;
    long expected = expected_text == NULL ? -1 : strtol(expected_text, &expected_end, 10);
    if (expected_text == NULL || expected_end == expected_text ||
        *expected_end != '\0' || errno != 0 || expected <= 0 || expected > INT_MAX ||
        getppid() != (pid_t)expected ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != (pid_t)expected) {
        fprintf(stderr, "ephem-jail requires its live, explicitly identified supervisor\n");
        return 125;
    }
    if (argc < 5 || strcmp(argv[1], "--root") != 0 ||
        strcmp(argv[3], "--worker") != 0 || argv[4][0] != '/') {
        fprintf(stderr, "usage: ephem-jail --root ROOTFS --worker /path [-- args...]\n");
        return 125;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "ephem-jail requires root for private namespaces and mounts\n");
        return 125;
    }
    if (reject_core_collector() < 0) {
        fprintf(stderr, "ephem-jail requires a readable, non-piped kernel core_pattern\n");
        return 125;
    }
    char root[PATH_MAX];
    if (validate_root(argv[2], root) < 0) {
        fprintf(stderr, "ephem-jail requires a trusted root-owned rootfs path\n");
        return 125;
    }
    for (int fd = 0; fd <= 2; fd++) {
        struct stat info;
        if (fstat(fd, &info) < 0 || S_ISSOCK(info.st_mode) ||
            (fd < 2 && !S_ISFIFO(info.st_mode))) {
            fprintf(stderr, "ephem-jail requires piped stdin/stdout and non-socket stderr\n");
            return 125;
        }
    }
    char **worker_argv = &argv[4];
    if (argc > 5 && strcmp(argv[5], "--") == 0) {
        argv[5] = argv[4];
        worker_argv = &argv[5];
    }
    struct sigaction action = {.sa_handler = catch_signal};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0)
        return 125;
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) < 0)
        return 125;
    int parent_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (parent_pidfd < 0)
        return 125;
    int pidfd = -1;
    struct clone_args arguments = {
        .flags = CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC |
                 CLONE_NEWUTS | CLONE_PIDFD,
        .pidfd = (uint64_t)(uintptr_t)&pidfd,
        .exit_signal = SIGCHLD,
    };
    pid_t child = (pid_t)syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (child < 0) {
        fprintf(stderr, "clone3: %s\n", strerror(errno));
        return 125;
    }
    if (child == 0)
        child_main(root, worker_argv, channel[1], parent_pidfd);
    close(channel[1]);
    close(parent_pidfd);
    int abi = 0;
    int status = supervise(child, pidfd, channel[0], &abi);
    close(pidfd);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    fprintf(stderr, "{\"ephem_jail\":1,\"worker_pid\":%ld,\"exit_code\":%d,"
        "\"signal\":%d,\"landlock_abi\":%d}\n",
        (long)child, exit_code, signal_number, abi);
    return signal_number != 0 ? 128 + signal_number : exit_code;
}
