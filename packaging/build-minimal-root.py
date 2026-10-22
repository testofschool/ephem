#!/usr/bin/env python3
"""Build a NEW public-input static-worker root and an external exact manifest.

This never scans or approves an arbitrary existing root. The caller must review
that the explicit worker is public and contains no embedded credentials. Hashes
establish identity, not the semantic absence of secrets. Partial outputs remain
for inspection on failure; the program never replaces or deletes a path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys


def canonical(path):
    value = str(path)
    if not value.startswith('/') or value == '/' or value.endswith('/'):
        raise ValueError('paths must be absolute, canonical, and non-root')
    for part in value.split('/')[1:]:
        if part in ('', '.', '..') or not all(c.isascii() and (c.isalnum() or c in '_.+-') for c in part):
            raise ValueError('path uses unsupported characters or components')
    return Path(value)


def ancestry(path):
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('parent ancestry must be root-owned, non-writable to group/world, without symlinks')


def static_elf(data):
    if len(data) < 64 or data[:4] != b'\x7fELF' or data[4] != 2 or data[5] not in (1, 2) or data[6] != 1:
        raise ValueError('worker must be a 64-bit static ELF executable')
    order = '<' if data[5] == 1 else '>'
    elf_type = struct.unpack_from(order + 'H', data, 16)[0]
    phoff = struct.unpack_from(order + 'Q', data, 32)[0]
    phsize, phcount = struct.unpack_from(order + 'HH', data, 54)
    if elf_type not in (2, 3) or phsize != 56 or not 1 <= phcount <= 1024 or phoff + phsize * phcount > len(data):
        raise ValueError('unsupported ELF program headers')
    if any(struct.unpack_from(order + 'I', data, phoff + index * phsize)[0] == 3 for index in range(phcount)):
        raise ValueError('dynamic interpreter is unsupported: explicit static worker required')


def build(worker, root, manifest):
    worker, root, manifest = (canonical(p) for p in (worker, root, manifest))
    if manifest == root or root in manifest.parents:
        raise ValueError('manifest must be outside the new root')
    ancestry(worker.parent)
    ancestry(root.parent)
    ancestry(manifest.parent)
    if os.path.lexists(root) or os.path.lexists(manifest):
        raise ValueError('root and manifest paths must be NEW')
    fd = os.open(worker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError('worker must be a root-owned trusted regular file without hardlinks')
        if info.st_size > 512 * 1024 * 1024:
            raise ValueError('worker exceeds public-root size limit')
        data = source.read(512 * 1024 * 1024 + 1)
        after = os.fstat(source.fileno())
        if len(data) != info.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise ValueError('worker changed while reading')
    static_elf(data)
    os.mkdir(root, 0o755)
    os.chmod(root, 0o755)
    os.mkdir(root / 'app', 0o555)
    os.chmod(root / 'app', 0o555)
    os.mkdir(root / 'tmp', 0o1777)
    os.chmod(root / 'tmp', 0o1777)
    fd = os.open(root / 'worker', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o555)
    with os.fdopen(fd, 'wb') as target:
        target.write(data)
        target.flush()
        os.fchmod(target.fileno(), 0o555)
    entries = [
        {'path': '/', 'kind': 'directory', 'mode': 0o755, 'bytes': 0, 'sha256': None},
        {'path': '/app', 'kind': 'directory', 'mode': 0o555, 'bytes': 0, 'sha256': None},
        {'path': '/tmp', 'kind': 'directory', 'mode': 0o1777, 'bytes': 0, 'sha256': None},
        {'path': '/worker', 'kind': 'file', 'mode': 0o555, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
    ]
    encoded = (json.dumps({'version': 1, 'entries': entries}, indent=2) + '\n').encode()
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    with os.fdopen(fd, 'wb') as target:
        target.write(encoded)
        target.flush()
        os.fchmod(target.fileno(), 0o444)
    return {'schema': 'ephem-minimal-public-root-build-v1', 'root': str(root), 'manifest': str(manifest),
            'worker_source': str(worker), 'worker_sha256': hashlib.sha256(data).hexdigest(),
            'manifest_sha256': hashlib.sha256(encoded).hexdigest(),
            'claim': 'Exact reviewed-worker inventory; no semantic secret detection or current-input confidentiality guarantee.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.geteuid() != 0:
        print('UNAVAILABLE: dedicated Linux root environment required', file=sys.stderr)
        return 77
    try:
        print(json.dumps(build(args.worker, args.root, args.manifest), indent=2))
        return 0
    except (OSError, ValueError) as error:
        print('minimal root refused: %s' % error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
