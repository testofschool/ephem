# Converter benchmark v1 — non-root probe (same host, 2026-10-27)

Host: the converter-bench-v1 host (Ubuntu 24.04.5, kernel 6.18.44, x86_64). `user.max_user_namespaces = 32025` (unprivileged user namespaces enabled on this host).
Worker: `/usr/bin/pdftotext /in/doc00.pdf -` over the same rootfs (`/opt/ephem-bench/pdf-root`), run as a non-root user `benchu` with no added capabilities.
Expected output sha256 (raw exec, pdftotext 24.02.0): `8b31b66f26100224fceb735076e4c6e46eed33f9b6640f69e48f025008453712`.

| Arm | Command (as `benchu`) | rc | stdout sha256 |
|---|---|---|---|
| bwrap 0.9.0 | `bwrap --unshare-all --ro-bind ROOTFS / --tmpfs /tmp --die-with-parent /usr/bin/pdftotext /in/doc00.pdf -` | 0 | 8b31b66f… (equal) |
| nsjail 4ff54a6e | `nsjail -Mo --chroot ROOTFS -T /tmp --disable_proc --quiet -- /usr/bin/pdftotext /in/doc00.pdf -` | 0 | 8b31b66f… (equal) |
| gVisor release-20261019.0 | `runsc --rootless --root=/tmp/gvu --network=none --ignore-cgroups run --bundle BUNDLE gvu2` | 0 | 8b31b66f… (equal) |
| EPHEM ephem-jail @380849c | `EPHEM_GATE_PID=<pid> ephem-jail --root ROOTFS --worker /usr/bin/pdftotext -- /in/doc00.pdf -` | 125 | stderr: `ephem-jail requires root for private namespaces and mounts` |

Not measured: any arm inside a Docker container with Docker's default seccomp profile, or on a host with unprivileged user namespaces disabled. n = 1 file per arm.
