/* Benign containment probes. This program is never installed in an application. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static unsigned char input[1048577];

static void emit(const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(STDOUT_FILENO, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) _exit(70);
        p += n;
        len -= (size_t)n;
    }
}

static int is_command(const char *s, size_t size) {
    return strlen(s) == size && memcmp(input, s, size) == 0;
}

static void fault(void) {
    /* A synchronous local fault, not a vulnerability or exploitation payload. */
    volatile uintptr_t address = 0;
    *(volatile unsigned char *)address = 1;
    _exit(71);
}

static void marker(void) {
    int fd = open("/tmp/marker", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) _exit(72);
    if (write(fd, "private request state", 21) != 21) _exit(73);
    close(fd);
}

int main(void) {
    size_t size = 0;
    for (;;) {
        ssize_t n = read(STDIN_FILENO, input + size, sizeof(input) - size);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return 74;
        if (n == 0) break;
        size += (size_t)n;
        if (size == sizeof(input)) return 75;
    }
    if (size >= 5 && memcmp(input, "ECHO ", 5) == 0) {
        emit(input + 5, size - 5);
    } else if (is_command("ID", size)) {
        char line[128];
        int len = snprintf(line, sizeof(line), "pid=%ld uid=%ld gid=%ld\n",
                           (long)getpid(), (long)geteuid(), (long)getegid());
        emit(line, (size_t)len);
    } else if (is_command("DIRTY", size)) {
        marker();
        emit("written\n", 8);
    } else if (is_command("DIRTYCRASH", size)) {
        marker();
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        fault();
    } else if (is_command("CLEAN", size)) {
        int fd = open("/tmp/marker", O_RDONLY);
        if (fd >= 0) {
            close(fd);
            emit("present\n", 8);
        } else if (errno == ENOENT) {
            emit("absent\n", 7);
        } else {
            return 76;
        }
    } else if (is_command("CRASH", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        fault();
    } else if (is_command("SOCKET", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) close(fd);
        return 77; /* Reaching this point means the syscall was not fatal. */
    } else if (is_command("HOSTWRITE", size)) {
        int fd = open("/app/sentinel", O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            if (write(fd, "changed", 7) != 7) return 81;
            close(fd);
            emit("write succeeded\n", 16);
        } else if (errno == EACCES || errno == EPERM || errno == EROFS) {
            /* Landlock returns errno. Catching that error is not a crash. */
            emit("denied\n", 7);
        } else {
            return 80;
        }
    } else if (is_command("FORK", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        pid_t child = fork();
        if (child == 0) _exit(78);
        return 77;
    } else if (is_command("EXEC", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        char *args[] = {"/worker", NULL};
        execv(args[0], args);
        return 77;
    } else if (is_command("HANG", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        for (;;) { __asm__ __volatile__("" ::: "memory"); }
    } else if (is_command("OUTPUT", size)) {
        unsigned char block[4096];
        memset(block, 'x', sizeof(block));
        for (unsigned i = 0; i < 513; ++i) emit(block, sizeof(block));
    } else if (is_command("FD", size)) {
        unsigned count = 0;
        for (int fd = 3; fd < 256; ++fd) {
            if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) ++count;
        }
        char line[64];
        int len = snprintf(line, sizeof(line), "extra_fds=%u\n", count);
        emit(line, (size_t)len);
    } else if (is_command("CAP", size)) {
        struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct caps[2] = {{0}, {0}};
        if (syscall(SYS_capget, &header, caps) != 0) return 79;
        char line[160];
        int len = snprintf(line, sizeof(line),
            "effective=%08x%08x permitted=%08x%08x inheritable=%08x%08x\n",
            caps[1].effective, caps[0].effective,
            caps[1].permitted, caps[0].permitted,
            caps[1].inheritable, caps[0].inheritable);
        emit(line, (size_t)len);
    } else if (is_command("READSECRET", size)) {
        /* Intentional counterexample: a successful response can exfiltrate
         * any file the application was allowed to read. Isolation is not DLP. */
        int fd = open("/app/fixture-secret", O_RDONLY);
        if (fd < 0) return 82;
        unsigned char secret[128];
        ssize_t n = read(fd, secret, sizeof(secret));
        close(fd);
        if (n < 0) return 83;
        emit(secret, (size_t)n);
    } else if (is_command("MEMORY", size)) {
        emit("SECRET_UNCOMMITTED_OUTPUT", 25);
        /* Touch real pages; virtual-address reservation alone is not an OOM
         * probe. 192MiB exceeds the test's cgroup limit, below RLIMIT_AS. */
        size_t bytes = 192U * 1024U * 1024U;
        volatile unsigned char *memory = malloc(bytes);
        if (memory == NULL) return 84;
        for (size_t index = 0; index < bytes; index += 4096) memory[index] = 1;
        return memory[0] == 1 ? 0 : 85;
    } else {
        return 64;
    }
    return 0;
}
