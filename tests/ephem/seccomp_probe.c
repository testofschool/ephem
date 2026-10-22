#define _GNU_SOURCE
#include "worker_containment.h"
#include <errno.h>
#include <linux/prctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One benign syscall per owned subprocess; no jail/app or host state fixture. */
int main(int argc, char **argv)
{
    if (argc != 2) return 64;
    int probe = -1;
    const char *names[] = {"peer0", "peer1", "vma0", "vma-high", "dumpable"};
    for (int index = 0; index < 5; ++index)
        if (strcmp(argv[1], names[index]) == 0) probe = index;
    if (probe < 0) return 64;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 65;
    int listener = ephem_install_seccomp(3);
    if (listener < 0) return 66;
    if (close(listener) != 0) return 67;
    errno = 0;
    long result;
    switch (probe) {
    case 0: result = syscall(SYS_getpeername, 0, NULL, NULL); break;
    case 1: result = syscall(SYS_getpeername, 1, NULL, NULL); break;
    case 2: result = syscall(SYS_prctl, 0x53564d41UL, 0UL, 0UL, 0UL, NULL); break;
    case 3: result = syscall(SYS_prctl, 0x53564d41UL, 1UL << 32, 0UL, 0UL, NULL); break;
    default: result = syscall(SYS_prctl, PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL); break;
    }
    int saved = errno;
    char line[80];
    int count = snprintf(line, sizeof(line), "result=%ld errno=%d\n", result, saved);
    if (count <= 0 || write(STDOUT_FILENO, line, (size_t)count) != count) return 68;
    int expected = probe == 0 ? ENOTSOCK : EINVAL;
    return (probe == 0 || probe == 2) && result == -1 && saved == expected ? 0 : 1;
}
