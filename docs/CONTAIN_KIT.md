# Contain kit: confine a document converter today, before the patch exists

When a critical bug lands in a converter you run on uploaded files, the patch can take days to reach your distro. This page gives you **measured, copy-paste recipes** for running five common converters under bubblewrap, nsjail or rootless gVisor **as a non-root user**, so you can drop one in the same hour.

Each recipe was checked for three things:

- the output is byte-identical to an unconfined run;
- the cost in milliseconds;
- the extra mounts the converter needs to keep working.

**What this is not:** confinement does not fix the bug. It limits what a compromised converter process can reach: no network, read-only system files, a private `/tmp`, and nothing outside the paths you bind. In a canary test, all three recipes failed to read a world-readable file outside the bound paths, which the same user reads without confinement ([log](../evidence/contain-kit-v1/canary.log)). Patch as soon as you can. Nothing on this page was tested against an exploit.

## Why these five
Ranked by how often they are named in 20 open GitHub issues asking to sandbox a document parser on untrusted input ([list](../evidence/contain-kit-v1/parser_demand.csv); collected 2026-10-28). Counts by the `parser_named` column: Poppler 5, Tesseract/OCR 5, PDFium 5, LibreOffice 4, pypdf/pdfminer 3, qpdf 1, Ghostscript 1, ImageMagick 1. PDFium and the Python parsers were **not measured** in this round.

Why now: OpenAI and Trail of Bits run "Patch the Planet", an AI-assisted vulnerability-research program on open-source projects. OpenAI reported "hundreds of security issues and merged dozens of patches", and CSO Online adds that more remain in coordinated disclosure ([CSO Online, 2026-06-23](https://www.csoonline.com/article/4188321/openai-rolls-out-ai-led-push-to-fix-open-source-software-flaws.html)). OpenAI credited the program for the October 2026 PHP2Shell findings ([AIbase, 2026-10-22](https://news.aibase.com/tw/news/31789)). This page does not claim to know which project is next.

## Results

Host: 2 vCPU x86_64 cloud VM, Ubuntu 24.04.5, kernel 6.18.44. Every run was made as an ordinary user (uid 30033) with no capabilities. Unprivileged user namespaces are **enabled** on this host. Inputs are small benign files: 10 one-page PDFs, 10 rendered PNGs, 5 text files. Each cell has 100 timed runs (LibreOffice: 20) after one warm-up round. Percentiles are nearest-rank. Across the four full runs made on 2026-10-28, the unconfined p50 moved by up to 1.7 ms for `pdftotext` and 26 ms for `tesseract`, so the smaller overheads below sit inside that noise (tesseract shows a negative one).

| Converter (version) | Arm | Output equal to unconfined | p50 ms | p95 ms | p50 overhead |
|---|---|---|---|---|---|
| `pdftotext` (Poppler 24.02.0) | none | 100/100 (reference) | 7.90 | 11.44 | — |
|  | bubblewrap 0.9.0 | 100/100 | 11.10 | 14.40 | +3.2 ms |
|  | nsjail 4ff54a6 | 100/100 | 13.80 | 17.78 | +5.9 ms |
|  | gVisor rootless | 100/100 | 126.06 | 155.98 | +118 ms |
| `pdftoppm` (Poppler 24.02.0) | none | 100/100 | 77.19 | 109.49 | — |
|  | bubblewrap 0.9.0 | 100/100 | 82.83 | 116.61 | +5.6 ms |
|  | nsjail 4ff54a6 | 100/100 | 84.16 | 119.16 | +7.0 ms |
|  | gVisor rootless | 100/100 | 246.91 | 307.94 | +170 ms |
| `tesseract` 5.3.4 (OCR) | none | 100/100 | 330.66 | 404.05 | — |
|  | bubblewrap 0.9.0 | 100/100 | 327.68 | 383.55 | −3.0 ms |
|  | nsjail 4ff54a6 | 100/100 | 320.48 | 372.67 | −10.2 ms |
|  | gVisor rootless | 100/100 | 573.24 | 728.38 | +243 ms |
| `qpdf --check` 11.9.0 | none | 100/100 | 3.78 | 4.95 | — |
|  | bubblewrap 0.9.0 | 100/100 | 6.91 | 8.81 | +3.1 ms |
|  | nsjail 4ff54a6 | 100/100 | 8.93 | 11.49 | +5.2 ms |
|  | gVisor rootless | 100/100 | 97.21 | 121.65 | +93.4 ms |
| `soffice --convert-to pdf` (LibreOffice 24.2.7) | none | 20/20 (text of output) | 297.93 | 331.25 | — |
|  | bubblewrap 0.9.0 | 20/20 | 462.26 | 541.81 | +164 ms |
|  | nsjail 4ff54a6 | 20/20 | 456.40 | 515.26 | +158 ms |
|  | gVisor rootless | 20/20 | 1457.34 | 1547.92 | +1159 ms |

For LibreOffice, "equal" compares the extracted text of the produced PDF, because the PDF itself embeds a timestamp. For `qpdf --check`, the input path it echoes is normalised before comparing, because gVisor sees the upload at `/in`. Raw samples, commands and the harness are in [`evidence/contain-kit-v1/`](../evidence/contain-kit-v1/). A second script recomputed all 20 cells from the CSVs and found 0 mismatches.

## Recipes (copy-paste)

Set `IN` to a read-only directory holding the upload and `OUT` to an empty directory the converter may write to.

**bubblewrap**
```sh
bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --setenv PATH /usr/bin:/bin --setenv HOME /tmp --setenv LANG C.UTF-8 \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --ro-bind /etc /etc --ro-bind /var/cache/fontconfig /var/cache/fontconfig \
  --ro-bind "$IN" "$IN" --bind "$OUT" "$OUT" --tmpfs /tmp --proc /proc --dev /dev \
  -- /usr/bin/pdftoppm -r 150 -png -singlefile "$IN/upload.pdf" "$OUT/page"
```

**nsjail**
```sh
nsjail -Mo --quiet -R /usr -s usr/bin:/bin -s usr/lib:/lib -s usr/lib64:/lib64 \
  -R /etc -R /var/cache/fontconfig -R /dev/null -R /dev/urandom \
  -R "$IN" -B "$OUT" -T /tmp -E PATH=/usr/bin:/bin -E HOME=/tmp -E LANG=C.UTF-8 --time_limit 60 \
  -- /usr/bin/pdftoppm -r 150 -png -singlefile "$IN/upload.pdf" "$OUT/page"
```

**gVisor (rootless):** an OCI bundle whose `root` is an empty skeleton directory (only `usr`, `etc`, `var/cache/fontconfig`, `tmp`, `proc`, `dev`, `in`, `out` and the `bin`/`lib`/`lib64` symlinks), with `/usr`, `/etc` and `/var/cache/fontconfig` bound read-only, the upload directory bound read-only at `/in`, the output directory bound read-write at `/out`, tmpfs `/tmp`, and `process.user` uid 0 (rootless mode maps it to the invoking user). Run it with `runsc --rootless --network=none --ignore-cgroups --overlay2=root:memory run`. The exact template is `evidence/contain-kit-v1/gv_config.json`.

Swap the final command for any converter in the table. The same mounts worked for all five.

## Four things that broke, and the fix that was measured

1. **Font cache.** Without `/var/cache/fontconfig` visible, `pdftoppm` under bubblewrap took 292–306 ms per call against 83–100 ms with it (3 runs each). The converter rebuilds the font cache on every call.
2. **LibreOffice under nsjail exits 0 and writes nothing** when `/dev/null` is missing ("dev/null: Directory nonexistent"). A wrapper that checks only the exit code reports success. With `-R /dev/null -R /dev/urandom` it produced 20/20 correct outputs. Check for the output file, not only the exit code.
3. **Rootless gVisor cannot write the output** when the container runs as uid 65534. Running as uid 0 inside rootless mode fixed it.
4. **A host `/` root exposes everything.** An earlier draft of the gVisor recipe used the host `/` as a read-only root. A review caught that this lets the converter read any file the user can read, and the canary test confirmed it (`canary-secret` was printed). The skeleton root above replaced it. That skeleton needs fixed mount points (`/in`, `/out`) and `--overlay2=root:memory`; without them the sandbox failed to start (rc 128).

## Limits
- Measured on a host where unprivileged user namespaces are allowed. Inside a Docker container with the default seccomp profile, or on a host that disables them, these recipes may refuse to start. **That case was not measured.**
- This repo's own EPHEM jail is not in the table because it requires root ([non-root probe](../evidence/converter-bench-v1-privilege/PRIVILEGE_PROBE.md)).
- The inputs are tiny and benign; large or hostile files will change the timings. One host, two vCPUs, and the arms ran one after another.
