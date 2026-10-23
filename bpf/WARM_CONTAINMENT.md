# Warm worker containment

The warm runtime installs its seccomp filter in each request child before
untrusted code. The additional `warm_containment.bpf.c` is an **optional BPF LSM
policy**. A compiled object alone provides no enforcement, and the warm daemon
does not currently load or depend on this optional object.

The LSM policy denies worker `execve` and `execveat` at `bprm_check_security`,
denies every new socket (including IPv4, IPv6 and UNIX), and denies connect,
bind, listen and accept. Existing AF_UNIX streams may carry the gate protocol.
Send/receive checks also deny use of mistakenly inherited Internet sockets.
`file_receive` denies descriptor import through SCM_RIGHTS. The trusted
supervisor must close every unrelated descriptor before forking a worker.

**An LSM denial cannot redirect a socket.** Applications must already use the
inherited gate stream or a supported adapter. This policy does not transparently
convert MySQL/PostgreSQL/Redis clients into gate clients.

Enrollment uses a BPF task-storage map keyed in userspace by a **pidfd**, avoiding
numeric-PID reuse. Only a quiescent, single-threaded trusted baseline is enrolled.
It must never run request code. At `task_alloc`, the LSM copies the generation
identifier into child task storage before the child can run. Every descendant
is labeled as a worker; allocation failure fails fork. Task storage is removed
by the kernel when its owning task is freed. Unenrolled tasks are unaffected.

Before each fork, a trusted supervisor must create a fresh nonzero generation
entry and update the stopped/quiescent baseline label. It must keep the entry
until **all** descendants have exited and been reaped. Any descendant denial
atomically sets a bit in the shared generation violation ledger. A denial is
recorded even if worker code catches EPERM and exits zero. Missing generation
state still denies restricted operations, and blocks further labeled forks.
Do not clear/reuse a live generation identifier. The optional loader example is
the dedicated self-test; integration of enrollment and these ledger checks into
the Rust supervisor is not implemented.

This LSM does not establish filesystem isolation, detect arbitrary memory
corruption, undo side effects, or implement database transactions. The runtime's
namespace, descriptor, filesystem and seccomp controls and transaction gate
remain necessary. A clean process exit cannot prove memory integrity.

## Build and kernel test

On a dedicated Linux x86_64/aarch64 system with clang's BPF backend, libbpf
headers/library, libelf and pkg-config:

```sh
sh bpf/build-warm-containment.sh /tmp/ephem-warm-bpf
sudo /tmp/ephem-warm-bpf/warm-containment-test \
    /tmp/ephem-warm-bpf/warm_containment.bpf.o
```

The compiler uses `-mcpu=v3` for atomic ledger updates. Kernel BTF and BPF LSM,
including `bpf` in `/sys/kernel/security/lsm`, are required. The self-test uses
libbpf to load the real object and attach **every** program before enrollment.
Any load, verifier or attachment error returns failure and unwinds all links.
It enrolls itself as a baseline, runs adversarial children and an inherited
grandchild, checks denied operations and the generation ledger, then checks a
clean fresh generation. No link or map is pinned after the test.

Exit 77 means **UNRUN: required root/active BPF LSM is unavailable**. It is not a
security test pass. Compilation is also not a verifier or enforcement pass.
The existing lab kernel `6.8.0-146-generic` lists
`lockdown,capability,landlock,yama,apparmor`; it has no active BPF LSM on this
boot. Consequently only compilation can be verified there without changing
the VM boot configuration.

Primary interfaces: [kernel BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html),
[kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[task-storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c),
and [LSM hook declarations](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h).
