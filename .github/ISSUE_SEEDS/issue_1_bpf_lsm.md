# [Kernel/LSM] Validate BPF LSM containment on kernels with active bpf in LSM list

The optional Phase 3 BPF LSM object and libbpf self-test compiled successfully on
Linux aarch64 `6.8.0-146-generic`, but the kernel load/enforcement test returned
**77 / UNRUN**. That boot exposed
`lockdown,capability,landlock,yama,apparmor` in `/sys/kernel/security/lsm`; `bpf`
was absent. Compilation is not verifier acceptance or enforcement evidence.
The measured Rust runtime enforces mandatory namespaces and classic seccomp;
it does not load or enroll workers in this optional LSM.

Please reproduce the dedicated self-test on a Linux x86_64 or aarch64 host with
an active BPF LSM. An example boot selection is
`lsm=lockdown,capability,landlock,yama,bpf`. This is an example to review against
the target distribution, not an instruction to replace its active LSM list:
preserve required existing modules (including AppArmor/SELinux where applicable),
and prefer a dedicated test VM already booted with `bpf` active. Do not change a
production host's security configuration for this experiment. Kernel BTF,
BPF LSM support, root, clang's BPF backend, libbpf development headers/library,
libelf and pkg-config are required.

From a fresh checkout at the revision being evaluated:

```sh
run_dir=$(mktemp -d /tmp/ephem-lsm-review.XXXXXX)
uname -a > "$run_dir/kernel.txt"
cat /sys/kernel/security/lsm > "$run_dir/active-lsm.txt"
sh bpf/build-warm-containment.sh "$run_dir/build"
if sudo "$run_dir/build/warm-containment-test" \
    "$run_dir/build/warm_containment.bpf.o" > "$run_dir/self-test.log" 2>&1; then
    result=0
else
    result=$?
fi
cat "$run_dir/self-test.log"
printf 'self-test exit=%s; evidence=%s\n' "$result" "$run_dir"
```

Attach the exact commit, architecture, kernel/config, active LSM list,
compiler/libbpf versions, full build/self-test logs and numeric exit status.
Report exit 77 as UNRUN and verifier/load/attachment failures as failures.
The test must load the object and attach every program before enrollment;
please retain verifier diagnostics on failure.

The current self-test exercises execve/execveat denial, IPv4/IPv6/UNIX socket
creation, inherited IPv4 use, descendant label inheritance, usable existing
local IPC, shared generation violations even after caught denials, and a fresh
clean generation. Enrollment uses pidfd-keyed task storage. No links/maps are
pinned by the self-test. Additional bind/listen/accept/descriptor-import probes
would be useful follow-up coverage; their hooks existing in the source alone
does not establish that these scenarios ran.

Success here would establish this optional object's behavior on the reported
kernel. Rust supervisor enrollment/generation-ledger integration remains a
separate task. LSM denial does not redirect database traffic, prove memory
integrity or supply transactions. Production remains **HOLD**.

Sources: [Phase 3 scope and results](https://github.com/testofschool/ephem/blob/main/docs/EPHEM_PHASE3.md),
[validation verdict](https://github.com/testofschool/ephem/blob/main/reports/phase3/VALIDATION.json),
[containment policy](https://github.com/testofschool/ephem/blob/main/bpf/warm_containment.bpf.c),
[libbpf self-test](https://github.com/testofschool/ephem/blob/main/bpf/warm_containment_test.c),
[BPF containment notes](https://github.com/testofschool/ephem/blob/main/bpf/WARM_CONTAINMENT.md).
