#!/usr/bin/env python3
"""Curate a new trusted root around the verified, patched PHP-CGI binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--php-cgi", type=Path, required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not args.rootfs.is_absolute() or args.rootfs.exists():
        parser.error("run as root with a new absolute dedicated rootfs path")
    if digest(args.app) != "c20a7b07a54d2341fca097d4e81e7e9d6ea1bcfda9b08deb62e1c9d4d711e681":
        parser.error("the unchanged receiver hash does not match")
    version = subprocess.run([str(args.php_cgi), "-n", "-v"], check=True,
                             capture_output=True, text=True).stdout
    if not version.startswith("PHP 8.3.36 (cgi-fcgi)"):
        parser.error("only the verified patched PHP 8.3.36 CGI is permitted")
    linked = subprocess.run(["ldd", str(args.php_cgi)], check=True,
                            capture_output=True, text=True).stdout
    if "not found" in linked:
        parser.error("unresolved PHP-CGI library")
    libraries = sorted(set(re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", linked,
                                     flags=re.MULTILINE)))
    args.rootfs.mkdir(mode=0o755)
    for folder, mode in [("tmp", 0o1777), ("app", 0o755), ("usr/bin", 0o755)]:
        target = args.rootfs / folder
        target.mkdir(mode=mode, parents=True, exist_ok=True)
        target.chmod(mode)
    sources = [(args.php_cgi, "/usr/bin/php-cgi"), (args.app, "/app/receiver.php")]
    sources += [(Path(library), library) for library in libraries]
    manifest = {"php_version": version.strip(), "ldd": linked,
                "application_source_sha256": digest(args.app), "files": []}
    for source, target in sources:
        destination = args.rootfs / target.lstrip("/")
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source, destination, follow_symlinks=True)
        destination.chmod(0o444 if target.endswith(".php") else 0o555)
        manifest["files"].append({"path": target, "bytes": destination.stat().st_size,
                                  "sha256": digest(destination)})
    (args.rootfs / ".ephem-php-rootfs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
