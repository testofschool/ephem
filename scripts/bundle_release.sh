#!/usr/bin/env bash
# Prepare a checked release locally. This script never invokes gh or publishes.
set -euo pipefail
umask 077
export LC_ALL=C

if [[ -L "${BASH_SOURCE[0]}" ]]; then
  printf '%s\n' 'ERROR: invoke the regular script, not a symlink.' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'UNRUN: python3 is required to prepare the release.' >&2
  exit 77
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

python3 - "$repo_root" "$@" <<'PY'
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

TAG = "v0.3.0-stateful-alpha"
TITLE = "v0.3.0-stateful-alpha: 0.52ms Stateful COW Runtime & Zero-Persistence Ledger"
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
CHUNK = 1024 * 1024
ROOT = Path(sys.argv[1])
ARTIFACT_DIR = "artifacts/ephem-phase3-linux-arm64"
VALIDATION = "reports/phase3/VALIDATION.json"
PROVENANCE = "reports/phase3/provenance-final.json"
NOTES = "docs/EPHEM_PHASE3.md"
ALIGNMENT = "reports/phase3/RELEASE_ALIGNMENT.json"
PRECHECK = "reports/phase3/REMOTE_SYNC_PRECHECK.json"
MEASURED_WORKSPACE = "reports/phase3/measured-workspace"
ALIGNMENT_RUNS = (
    "reports/phase3/release-alignment-final",
    "reports/phase3/release-alignment-run1",
    "reports/phase3/release-alignment-run3",
    "reports/phase3/remote-sync-run",
)
BINARIES = {
    "ephem-stateful": "target/release/ephem-stateful",
    "ephem-warm-pool": "target/release/ephem-warm-pool",
    "libephem_php.so": "target/phase3/libephem_php.so",
}
DOWNLOAD_ASSETS = (
    "artifacts/ephem-phase3-linux-arm64.tar.gz",
    "SHA256SUMS.txt",
    "RELEASE_ALIGNMENT.json",
    "REMOTE_SYNC_PRECHECK.json",
)
CANONICAL_STAGE = f"artifacts/release-phase3/{TAG}"
ARM64_ARCHIVE = "artifacts/ephem-phase3-linux-arm64.tar.gz"
# Published v0.3.0 asset identity, preserved by this evidence-only addendum.
ARM64_ARCHIVE_SHA256 = "d8edad0b10ed8dbcf59a23787f1439649a842bff0c2a6b3ba6c5a2be03a09dca"
X86_DIRECTORY = "evidence/x86-independent-v1"
X86_ARCHIVE = "artifacts/ephem-phase3-x86_64-evidence.tar.gz"
X86_FILES = (
    "X86_REPRODUCTION.json", "binary-sha256.txt", "cargo-build.log", "cargo-test.log",
    "env.txt", "upstream-commit.txt", "warm-native.json", "warm-native.stderr.log",
)
ADDENDUM_FILES = (
    "README.md", ".github/workflows/ci.yml", "scripts/bundle_release.sh",
    "scripts/verify_stored_evidence.py", "scripts/verify_x86_evidence.py",
    "tests/test_stored_evidence.py", "tests/test_x86_evidence.py",
    "tests/test_phase3_release_bundle.py",
)


def fail(message):
    raise ValueError(message)


def relative(name):
    path = PurePosixPath(name)
    if (not isinstance(name, str) or not name or path.is_absolute()
            or str(path) != name or any(p in (".", "..") for p in path.parts)
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)):
        fail(f"unsafe repository-relative path: {name!r}")
    return path


def open_source(name):
    """Open each path component without following any symlink."""
    parts = relative(name).parts
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
    finally:
        os.close(directory)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        os.close(descriptor)
        fail(f"not a bounded regular file: {name}")
    return os.fdopen(descriptor, "rb")


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def digest_source(name, destination=None):
    with open_source(name) as source:
        before = os.fstat(source.fileno())
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_FILE:
                fail(f"file grew beyond size limit: {name}")
            digest.update(chunk)
            if destination is not None:
                destination.write(chunk)
        if fingerprint(before) != fingerprint(os.fstat(source.fileno())):
            fail(f"file changed while reading: {name}")
    return {"sha256": digest.hexdigest(), "bytes": count}


def read_source(name):
    with open_source(name) as source:
        before = os.fstat(source.fileno())
        if before.st_size > 16 * 1024 * 1024:
            fail(f"metadata exceeds 16 MiB: {name}")
        data = source.read(16 * 1024 * 1024 + 1)
        if (len(data) > 16 * 1024 * 1024
                or fingerprint(before) != fingerprint(os.fstat(source.fileno()))):
            fail(f"metadata changed or exceeded its bound: {name}")
    return data


def expected_record(record, label):
    if (not isinstance(record, dict)
            or not re.fullmatch(r"[a-f0-9]{64}", str(record.get("sha256", "")))
            or type(record.get("bytes")) is not int
            or not 0 <= record["bytes"] <= MAX_FILE):
        fail(f"invalid hash/size provenance for {label}")
    return {"sha256": record["sha256"], "bytes": record["bytes"]}


def checked(name, record):
    actual = digest_source(name)
    if actual != expected_record(record, name):
        fail(f"recorded provenance mismatch: {name}")
    return actual


def checked_sources(sources):
    """Preserve measured sources while allowing one public package version bump."""
    snapshots = {}
    for name in ("Cargo.lock", "Cargo.toml"):
        snapshot = f"{MEASURED_WORKSPACE}/{name}"
        checked(snapshot, sources.get(name))
        snapshots[name] = read_source(snapshot)
    exceptions = []
    for name, record in sorted(sources.items()):
        actual = digest_source(name)
        expected = expected_record(record, name)
        if actual == expected:
            continue
        old = b'[[package]]\nname = "ephem-gate"\nversion = "0.1.0"\n'
        new = b'[[package]]\nname = "ephem-gate"\nversion = "0.2.0"\n'
        if (name != "Cargo.lock" or snapshots[name].count(old) != 1
                or read_source(name) != snapshots[name].replace(old, new, 1)):
            fail(f"recorded provenance mismatch: {name}")
        exceptions.append({
            "path": name, "recorded": expected, "current": actual,
            "measured_snapshot": f"{MEASURED_WORKSPACE}/{name}",
            "allowed_change": "Exactly one ephem-gate package version: 0.1.0 -> 0.2.0",
            "reason": "Preserve the public main branch ephem-gate v0.2 package metadata; "
                      "measured Phase 3 runtime sources and deliverable binary hashes are unchanged.",
        })
    return exceptions


def write_bytes(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with path.open("xb") as output:
        output.write(data)
    path.chmod(mode)


def write_json(path, data):
    write_bytes(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def all_files(directory):
    files = []
    for parent, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs + names:
            candidate = Path(parent) / name
            if candidate.is_symlink():
                fail(f"symlink in staging/output: {candidate}")
            if not (candidate.is_dir() or candidate.is_file()):
                fail(f"special file in staging/output: {candidate}")
        files.extend(Path(parent) / name for name in names)
        if len(files) > 2048:
            fail(f"too many files in staging/output: {directory}")
    return sorted(files, key=lambda p: p.relative_to(directory).as_posix())


def checksum_bytes(directory):
    return "".join(f"{file_digest(path)}  {path.relative_to(directory).as_posix()}\n"
                   for path in all_files(directory)
                   if path.name != "SHA256SUMS.txt").encode()


def ensure_output_parent(parts):
    current = ROOT
    for part in parts:
        current = current / part
        try:
            current.mkdir(mode=0o755)
        except FileExistsError:
            pass
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            fail(f"output parent must be a real directory: {current}")
    return current


def same_tree(first, second):
    def inventory(directory):
        if not stat.S_ISDIR(directory.lstat().st_mode):
            fail(f"existing output is not a real directory: {directory}")
        return [(p.relative_to(directory).as_posix(), p.stat().st_mode & 0o777,
                 file_digest(p)) for p in all_files(directory)]
    return inventory(first) == inventory(second)


def write_root_checksums(output_dir, addendum=False):
    names = {path.relative_to(ROOT).as_posix() for path in all_files(output_dir)}
    if addendum:
        for directory in (X86_DIRECTORY, "docs/audit"):
            names.update(path.relative_to(ROOT).as_posix()
                         for path in all_files(ROOT / directory)
                         if "__pycache__" not in path.parts and path.suffix != ".pyc")
        names.update(name for name in ADDENDUM_FILES if (ROOT / name).exists())
    data = "".join(f"{digest_source(name)['sha256']}  {name}\n"
                   for name in sorted(names)).encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".SHA256SUMS-", dir=ROOT)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        os.chmod(temporary, 0o644)
        if (ROOT / "SHA256SUMS.txt").is_symlink():
            fail("repository SHA256SUMS.txt became a symlink")
        os.replace(temporary, ROOT / "SHA256SUMS.txt")
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def deterministic_archive(directory, archive):
    archive.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with archive.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
                for path in all_files(directory):
                    info = tarfile.TarInfo(path.relative_to(directory).as_posix())
                    info.size = path.stat().st_size
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with path.open("rb") as source:
                        tar.addfile(info, source)
    archive.chmod(0o644)


def stage_checksums(stage, assets):
    names = sorted({ARM64_ARCHIVE, NOTES, "RELEASE_ALIGNMENT.json",
                    "REMOTE_SYNC_PRECHECK.json"} | ({X86_ARCHIVE} if X86_ARCHIVE in assets else set()))
    return "".join(f"{file_digest(stage / name)}  {name}\n" for name in names).encode()


def download_checksums(stage, assets):
    return "".join(f"{file_digest(stage / name)}  {PurePosixPath(name).name}\n"
                   for name in assets).encode()


def validate_existing_stage(stage):
    if not stat.S_ISDIR(stage.lstat().st_mode):
        fail(f"existing output is not a real directory: {stage}")
    names = {p.relative_to(stage).as_posix() for p in all_files(stage)}
    base = {ARM64_ARCHIVE, NOTES, "RELEASE_ALIGNMENT.json", "REMOTE_SYNC_PRECHECK.json",
            "SHA256SUMS.txt", "DOWNLOAD_SHA256SUMS.txt"}
    if names not in (base, base | {X86_ARCHIVE}):
        fail(f"unexpected existing release-stage inventory: {stage}")
    if file_digest(stage / ARM64_ARCHIVE) != ARM64_ARCHIVE_SHA256:
        fail("published ARM64 archive identity differs; refusing evidence addendum")
    for staged, source in ((NOTES, NOTES), ("RELEASE_ALIGNMENT.json", ALIGNMENT),
                           ("REMOTE_SYNC_PRECHECK.json", PRECHECK)):
        if (stage / staged).read_bytes() != read_source(source):
            fail(f"original staged release file differs: {staged}")
    assets = DOWNLOAD_ASSETS + ((X86_ARCHIVE,) if X86_ARCHIVE in names else ())
    if (stage / "SHA256SUMS.txt").read_bytes() != stage_checksums(stage, assets):
        fail(f"existing staged checksums differ: {stage}")
    if (stage / "DOWNLOAD_SHA256SUMS.txt").read_bytes() != download_checksums(stage, assets):
        fail(f"existing flat-download checksums differ: {stage}")


def prepare_x86_addendum(output_relative):
    evidence = ROOT / X86_DIRECTORY
    if not stat.S_ISDIR(evidence.lstat().st_mode):
        fail("x86 evidence must be a real directory")
    if [p.relative_to(evidence).as_posix() for p in all_files(evidence)] != sorted(X86_FILES):
        fail("x86 addendum requires exactly the original eight evidence files")
    records = {name: digest_source(f"{X86_DIRECTORY}/{name}") for name in X86_FILES}
    # The portable verifier reads stored bytes only; no binary or benchmark runs.
    read_source("scripts/verify_x86_evidence.py")
    result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/verify_x86_evidence.py")],
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or json.loads(result.stdout).get("status") != "PASS":
        fail("x86 stored-evidence verification failed: " + result.stdout + result.stderr)
    canonical = ROOT / CANONICAL_STAGE
    validate_existing_stage(canonical)
    parent = ensure_output_parent(output_relative.parts[:-1])
    lock = ROOT / "artifacts/release-phase3/.bundle.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        fail(f"another bundle operation or stale lock exists: {lock}; inspect it before retrying")
    scratch = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".bundle-", dir=parent))
        payload, stage = scratch / "x86", scratch / "stage"
        payload.mkdir(mode=0o755)
        stage.mkdir(mode=0o755)
        for name in sorted(X86_FILES):
            with (payload / name).open("xb") as output:
                actual = digest_source(f"{X86_DIRECTORY}/{name}", output)
            if actual != records[name]:
                fail(f"x86 evidence changed before staging: {name}")
            (payload / name).chmod(0o644)
        write_bytes(payload / "SHA256SUMS.txt", checksum_bytes(payload))
        deterministic_archive(payload, stage / X86_ARCHIVE)
        for name in (ARM64_ARCHIVE, NOTES, "RELEASE_ALIGNMENT.json", "REMOTE_SYNC_PRECHECK.json"):
            source = f"{CANONICAL_STAGE}/{name}"
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with destination.open("xb") as output:
                digest_source(source, output)
            destination.chmod(0o644)
        if file_digest(stage / ARM64_ARCHIVE) != ARM64_ARCHIVE_SHA256:
            fail("published ARM64 archive changed before staging")
        assets = DOWNLOAD_ASSETS + (X86_ARCHIVE,)
        write_bytes(stage / "SHA256SUMS.txt", stage_checksums(stage, assets))
        write_bytes(stage / "DOWNLOAD_SHA256SUMS.txt", download_checksums(stage, assets))
        # Recheck original receipts and their checksum layers after copying.
        validate_existing_stage(stage)
        if ((canonical / X86_ARCHIVE).exists()
                and file_digest(canonical / X86_ARCHIVE) != file_digest(stage / X86_ARCHIVE)):
            fail("canonical x86 evidence archive differs; preserving it")
        output_dir = ROOT / str(output_relative)
        if output_dir.exists() or output_dir.is_symlink():
            validate_existing_stage(output_dir)
            if ((output_dir / X86_ARCHIVE).exists()
                    and file_digest(output_dir / X86_ARCHIVE) != file_digest(stage / X86_ARCHIVE)):
                fail("existing x86 evidence archive differs; preserving it")
            for name in (X86_ARCHIVE, "SHA256SUMS.txt", "DOWNLOAD_SHA256SUMS.txt"):
                os.replace(stage / name, output_dir / name)
        else:
            os.rename(stage, output_dir)
            output_dir.chmod(0o755)
        write_root_checksums(output_dir, addendum=True)
        print(f"Prepared evidence addendum: {output_dir}")
        print(f"Preserved published ARM64 archive SHA-256: {ARM64_ARCHIVE_SHA256}")
        print("Verified: eight stored x86 files; deterministic evidence archive; no binaries executed.")
        print("Production: HOLD. PHP paired latency gate: FAIL; PostgreSQL/BPF gaps unchanged.")
        print("Flat download checksums cover five assets; upload stage checksum files, not repository sums.")
        print(f"cd -- {shlex.quote(str(output_dir))}")
        print(f"gh release upload {TAG} --repo testofschool/ephem "
              f"{X86_ARCHIVE} SHA256SUMS.txt DOWNLOAD_SHA256SUMS.txt --clobber")
    finally:
        if scratch is not None:
            shutil.rmtree(scratch)
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(
        description="Prepare verified Phase 3 assets; no upload or publication occurs.")
    parser.add_argument("--output", default=f"artifacts/release-phase3/{TAG}",
                        help="repository-relative staging directory under artifacts/release-phase3")
    args = parser.parse_args(sys.argv[2:])
    output_relative = relative(args.output)
    if (output_relative.parts[:2] != ("artifacts", "release-phase3")
            or len(output_relative.parts) < 3):
        fail("--output must be a directory under artifacts/release-phase3/")
    root_checksums = ROOT / "SHA256SUMS.txt"
    if root_checksums.exists() or root_checksums.is_symlink():
        if not stat.S_ISREG(root_checksums.lstat().st_mode):
            fail("repository SHA256SUMS.txt must be a regular file, never a symlink")

    metadata = {VALIDATION: read_source(VALIDATION), PROVENANCE: read_source(PROVENANCE),
                NOTES: read_source(NOTES), ALIGNMENT: read_source(ALIGNMENT),
                PRECHECK: read_source(PRECHECK)}
    validation = json.loads(metadata[VALIDATION])
    provenance = json.loads(metadata[PROVENANCE])
    alignment = json.loads(metadata[ALIGNMENT])
    precheck = json.loads(metadata[PRECHECK])
    if (validation.get("schema") != "ephem.phase3.validation.v1"
            or validation.get("production_status") != "HOLD"
            or validation.get("implementation_status") != "BOUNDED_IMPLEMENTATION_VERIFIED"
            or provenance.get("schema") != "ephem.phase3.provenance.v1"
            or provenance.get("machine") != "aarch64"):
        fail("expected bounded Linux ARM64 validation/provenance and Production HOLD")
    if (alignment.get("schema") != "ephem.phase3.release-alignment.v1"
            or alignment.get("production_status") != "HOLD"):
        fail("expected historical Phase 3 release alignment and Production HOLD")
    if (precheck.get("schema") != "ephem.phase3.remote-sync-precheck.v1"
            or precheck.get("production_status") != "HOLD"):
        fail("expected remote-sync precheck receipt and Production HOLD")

    # Source hashes prevent an old measured binary from being advertised as a
    # verified build of different runtime sources. New docs/scripts are outside
    # the frozen source inventory and do not rewrite that evidence.
    sources = provenance.get("source_files")
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 1024:
        fail("missing or excessive source provenance inventory")
    source_exceptions = checked_sources(sources)

    asset_path = ROOT / ARTIFACT_DIR
    packaged = asset_path.exists() or asset_path.is_symlink()
    if packaged:
        if not stat.S_ISDIR(asset_path.lstat().st_mode):
            fail(f"{ARTIFACT_DIR} must be a real directory")
        inventory = [p.relative_to(asset_path).as_posix() for p in all_files(asset_path)]
        if inventory != sorted(["README.md", *BINARIES]):
            fail(f"unexpected or incomplete ARM64 artifact inventory: {inventory}")

    binary_sources = {}
    binary_records = {}
    for name, original in BINARIES.items():
        first = expected_record(validation.get("tested_binaries", {}).get(original), original)
        second = expected_record(provenance.get("binaries", {}).get(original), original)
        if first != second:
            fail(f"validation and provenance disagree for {original}")
        source = f"{ARTIFACT_DIR}/{name}" if packaged else original
        checked(source, first)
        with open_source(source) as binary:
            header = binary.read(20)
        if (len(header) != 20 or header[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(header[18:20], "little") != 183):
            fail(f"not a Linux ARM64 ELF64 deliverable: {source}")
        binary_sources[f"{ARTIFACT_DIR}/{name}"] = source
        binary_records[name] = first

    # Gather the frozen evidence inventory, linked reports, and explicitly named
    # alignment runs. Never glob artifacts/ or unrelated runtime/cluster state.
    notes = metadata[NOTES]
    report_names = set(validation.get("reports", []))
    report_names.update(validation.get("retained_failures", []))
    report_names.add(validation["checks"]["actual_postgres_adapter_fixture"]["evidence"])
    linked_reports = set()
    for link in re.findall(r"\]\((\.\./reports/phase3/[^)#]+)\)", notes.decode()):
        candidate = link[3:]
        if candidate.rstrip("/") in (*ALIGNMENT_RUNS, MEASURED_WORKSPACE):
            # These directories are gathered by explicit inventory below.
            continue
        linked_reports.add(str(relative(candidate)))
    if not 1 <= len(report_names) <= 256:
        fail("missing or excessive Phase 3 report inventory")
    frozen = {VALIDATION, PROVENANCE}
    for name in report_names:
        if not isinstance(name, str) or "/" in name:
            fail(f"unsafe Phase 3 report name: {name!r}")
        frozen.add(f"reports/phase3/{name}")

    evidence_name = "reports/phase3/evidence-manifest-final.json"
    metadata[evidence_name] = read_source(evidence_name)
    evidence = json.loads(metadata[evidence_name])
    if evidence.get("schema") != "ephem.phase3.evidence-manifest.v1":
        fail("invalid Phase 3 evidence manifest")
    # Keep the original frozen evidence manifest byte-identical, and check its
    # entire inventory. New alignment runs have a separate release-bundle record.
    evidence_files = evidence.get("files")
    if not isinstance(evidence_files, dict) or not 1 <= len(evidence_files) <= 256:
        fail("missing or excessive frozen evidence inventory")
    frozen.update(evidence_files)
    for name in sorted(frozen):
        if not str(relative(name)).startswith("reports/phase3/"):
            fail(f"unexpected frozen evidence path: {name}")
        checked(name, evidence_files.get(name))
    selected = frozen | linked_reports | {
        NOTES, ALIGNMENT, PRECHECK, evidence_name, "docs/LINUX_LAB.md", "bpf/WARM_CONTAINMENT.md",
        f"{MEASURED_WORKSPACE}/Cargo.lock", f"{MEASURED_WORKSPACE}/Cargo.toml",
        "reports/phase3/release-alignment-run2.failed.log",
        "reports/phase3/release-alignment-unit-tests.log",
    }
    for directory in ALIGNMENT_RUNS:
        # Only these explicitly named run directories are gathered, never
        # arbitrary reports/, runtime state, or private cluster logs.
        files = all_files(ROOT / directory)
        if not files:
            fail(f"required alignment run has no regular evidence files: {directory}")
        selected.update(path.relative_to(ROOT).as_posix() for path in files)
    if not 1 <= len(selected) <= 1024:
        fail("missing or excessive release evidence inventory")
    input_map = {name: name for name in selected}
    input_map.update(binary_sources)
    if packaged:
        input_map[f"{ARTIFACT_DIR}/README.md"] = f"{ARTIFACT_DIR}/README.md"

    if (ROOT / X86_DIRECTORY).exists() or (ROOT / X86_DIRECTORY).is_symlink():
        prepare_x86_addendum(output_relative)
        return

    parent = ensure_output_parent(output_relative.parts[:-1])
    lock = ROOT / "artifacts/release-phase3/.bundle.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        fail(f"another bundle operation or stale lock exists: {lock}; inspect it before retrying")
    scratch = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".bundle-", dir=parent))
        payload = scratch / "payload"
        stage = scratch / "stage"
        payload.mkdir(mode=0o755)
        stage.mkdir(mode=0o755)
        manifest = {}
        total_bytes = 0
        for destination, source in sorted(input_map.items()):
            path = payload / destination
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with path.open("xb") as output:
                record = digest_source(source, output)
            if source in metadata and record != {
                    "sha256": hashlib.sha256(metadata[source]).hexdigest(),
                    "bytes": len(metadata[source])}:
                fail(f"metadata changed before staging: {source}")
            total_bytes += record["bytes"]
            if total_bytes > MAX_TOTAL:
                fail("bundle inputs exceed 512 MiB")
            if destination.startswith(ARTIFACT_DIR + "/") and path.name in BINARIES:
                if record != binary_records[path.name]:
                    fail(f"binary changed before staging: {source}")
                path.chmod(0o755)
            else:
                path.chmod(0o644)
            manifest[destination] = {**record, "source": source}

        # Recheck frozen evidence after copying; verification applies to exactly
        # the copied bytes, including metadata, rather than a pre-copy snapshot.
        for name in sorted(frozen):
            if {k: manifest[name][k] for k in ("sha256", "bytes")} != expected_record(
                    evidence_files[name], name):
                fail(f"evidence changed before staging: {name}")
        for name in ("Cargo.lock", "Cargo.toml"):
            snapshot = f"{MEASURED_WORKSPACE}/{name}"
            if {k: manifest[snapshot][k] for k in ("sha256", "bytes")} != expected_record(
                    sources[name], name):
                fail(f"measured source snapshot changed before staging: {snapshot}")
        write_json(payload / "RELEASE_BUNDLE.json", {
            "schema": "ephem.phase3.release-bundle.v1", "tag": TAG, "title": TITLE,
            "production_status": "HOLD", "platform": "linux-aarch64",
            "binary_selection": "recorded-arm64-artifacts" if packaged else "recorded-target-builds",
            "verified_source_files": len(sources),
            "exact_source_hash_matches": len(sources) - len(source_exceptions),
            "source_metadata_exceptions": source_exceptions,
            "historical_alignment": {
                "path": ALIGNMENT,
                "context": "Original local execution report preserved verbatim; "
                           "its published:false and git_context describe that earlier execution.",
                "native_p95_ms": alignment["verification"]["native_latency_ms"]["p95_ms"],
            },
            "remote_sync_precheck": {
                "path": PRECHECK,
                "context": "The new integrated run is preserved with all observed failures; "
                           "successful packaging verifies bytes, not a passing benchmark gate.",
            },
            "files": manifest,
            "limitations": [
                "Packaging verifies recorded hashes; it does not rerun Linux tests.",
                "Dynamic PHP 8.3 NTS embed and Linux system dependencies are required.",
                "Reproduction source is in the repository; this is not a standalone source distribution.",
                "BPF LSM kernel enforcement remains UNRUN, and production remains HOLD.",
                "Recorded binaries were measured with the preserved Cargo.lock snapshot; "
                "the public repository may include the explicitly recorded ephem-gate version-only exception.",
                "The remote-sync integrated PHP paired latency gate failed; "
                "consult REMOTE_SYNC_PRECHECK.json and reports/phase3/remote-sync-run/.",
            ],
        })
        write_bytes(payload / "SHA256SUMS.txt", checksum_bytes(payload))
        archive = stage / "artifacts/ephem-phase3-linux-arm64.tar.gz"
        archive.parent.mkdir(mode=0o755)
        archive.parent.chmod(0o755)
        with archive.open("xb") as output:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
                    for path in all_files(payload):
                        info = tarfile.TarInfo(path.relative_to(payload).as_posix())
                        info.size = path.stat().st_size
                        info.mode = path.stat().st_mode & 0o777
                        info.mtime = 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        with path.open("rb") as source:
                            tar.addfile(info, source)
        archive.chmod(0o644)
        write_bytes(stage / NOTES, (payload / NOTES).read_bytes())
        write_bytes(stage / "RELEASE_ALIGNMENT.json", (payload / ALIGNMENT).read_bytes())
        write_bytes(stage / "REMOTE_SYNC_PRECHECK.json", (payload / PRECHECK).read_bytes())
        (stage / "docs").chmod(0o755)
        write_bytes(stage / "SHA256SUMS.txt", checksum_bytes(stage))
        # GitHub flattens uploaded asset paths. Keep the stage/archive manifests
        # intact and add a separate manifest for the exact flat download layout.
        # It excludes itself to avoid a checksum cycle; repository sums cover it.
        download_checksums = "".join(
            f"{file_digest(stage / name)}  {PurePosixPath(name).name}\n"
            for name in DOWNLOAD_ASSETS).encode()
        write_bytes(stage / "DOWNLOAD_SHA256SUMS.txt", download_checksums)
        output_dir = ROOT / str(output_relative)
        if output_dir.exists() or output_dir.is_symlink():
            if not same_tree(stage, output_dir):
                fail(f"existing bundle differs; preserved {output_dir}; choose a new --output")
        else:
            os.rename(stage, output_dir)
            output_dir.chmod(0o755)
        # The repository checkpoint checks every staged regular file, including
        # its own checksum manifest. The payload has its own original-file sums.
        write_root_checksums(output_dir)
        print(f"Prepared: {output_dir}")
        print(f"Verified: {len(BINARIES)} measured ARM64 binaries, "
              f"{len(sources) - len(source_exceptions)} exact source hashes, "
              f"{len(source_exceptions)} explicit version-only source exception(s), "
              f"{len(manifest)} gathered files")
        print("Checksums: SHA256SUMS.txt (repository); SHA256SUMS.txt (stage and archive)")
        print("Flat GitHub downloads: DOWNLOAD_SHA256SUMS.txt (four uploaded assets)")
        print("Production: HOLD. Packaging only; no tests rerun and nothing published.")
        print("New integrated PHP paired latency gate: FAIL; raw evidence included, no benchmark retry.")
        print("\nReview the bundle, then run this command only after publication approval:\n")
        print(f"cd -- {shlex.quote(str(output_dir))}")
        print(f"gh release create {TAG} \\")
        print("  --repo testofschool/ephem \\")
        print(f"  --title {shlex.quote(TITLE)} \\")
        print("  --notes-file docs/EPHEM_PHASE3.md \\")
        print("  artifacts/ephem-phase3-linux-arm64.tar.gz SHA256SUMS.txt \\")
        print("  RELEASE_ALIGNMENT.json REMOTE_SYNC_PRECHECK.json DOWNLOAD_SHA256SUMS.txt")
    finally:
        if scratch is not None:
            shutil.rmtree(scratch)
        lock.rmdir()


try:
    main()
except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
    print(f"ERROR: release bundle not prepared: {error}", file=sys.stderr)
    sys.exit(1)
PY
