"""Exercise the real bundle, all checksum layers, and source-drift rejection."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FROZEN = (
    'reports/phase3/VALIDATION.json',
    'reports/phase3/provenance-final.json',
    'reports/phase3/evidence-manifest-final.json',
    'reports/phase3/RELEASE_ALIGNMENT.json',
)
PRECHECK = 'reports/phase3/REMOTE_SYNC_PRECHECK.json'
STAGE = 'artifacts/release-phase3/v0.3.0-stateful-alpha'
ARM64 = 'artifacts/ephem-phase3-linux-arm64.tar.gz'
ARM64_SHA256 = 'd8edad0b10ed8dbcf59a23787f1439649a842bff0c2a6b3ba6c5a2be03a09dca'
X86 = 'artifacts/ephem-phase3-x86_64-evidence.tar.gz'
X86_DIRECTORY = 'evidence/x86-independent-v1'
BASE_FILES = (ARM64, 'docs/EPHEM_PHASE3.md', 'RELEASE_ALIGNMENT.json', 'REMOTE_SYNC_PRECHECK.json')
DOWNLOAD_FILES = (ARM64, 'SHA256SUMS.txt', 'RELEASE_ALIGNMENT.json', 'REMOTE_SYNC_PRECHECK.json')


class Phase3ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='.bundle-test-', dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        provenance = json.loads((ROOT / FROZEN[1]).read_text())
        inputs = set(provenance['source_files']) | {
            'scripts/bundle_release.sh', 'docs/EPHEM_PHASE3.md',
            'docs/LINUX_LAB.md', 'bpf/WARM_CONTAINMENT.md',
        }
        for directory in ('reports/phase3', 'artifacts/ephem-phase3-linux-arm64'):
            inputs.update(path.relative_to(ROOT).as_posix()
                          for path in (ROOT / directory).rglob('*') if path.is_file())
        for name in sorted(inputs):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        # A failed new gate is a valid release attachment under explicit HOLD.
        # This fixture stays inside the isolated test checkout.
        self.precheck = (json.dumps({
            'schema': 'ephem.phase3.remote-sync-precheck.v1',
            'production_status': 'HOLD',
            'php_paired_latency_gate': {'status': 'FAIL', 'p95_ms': 3.730803},
        }, indent=2) + '\n').encode()
        (self.root / PRECHECK).write_bytes(self.precheck)
        fixture = self.root / 'reports/phase3/remote-sync-run/bundler-fixture-failed-gate.log'
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text('PHP paired latency gate: FAIL; no benchmark retry.\n')
        self.frozen = {name: (self.root / name).read_bytes() for name in FROZEN}

    def bundle(self, *args):
        return subprocess.run(
            ['bash', 'scripts/bundle_release.sh', *args], cwd=self.root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
        )

    def assert_checksums(self, data, read):
        names = set()
        for line in data.decode().splitlines():
            expected, name = line.split('  ', 1)
            self.assertNotIn(name, names)
            names.add(name)
            self.assertEqual(hashlib.sha256(read(name)).hexdigest(), expected, name)
        self.assertTrue(names)
        return names

    def test_real_bundle_has_complete_checked_evidence_and_metadata_exception(self):
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        stage = self.root / 'artifacts/release-phase3/v0.3.0-stateful-alpha'
        root_names = self.assert_checksums(
            (self.root / 'SHA256SUMS.txt').read_bytes(),
            lambda name: (self.root / name).read_bytes(),
        )
        stage_names = self.assert_checksums(
            (stage / 'SHA256SUMS.txt').read_bytes(),
            lambda name: (stage / name).read_bytes(),
        )
        self.assertEqual(stage_names, {
            'artifacts/ephem-phase3-linux-arm64.tar.gz', 'docs/EPHEM_PHASE3.md',
            'RELEASE_ALIGNMENT.json', 'REMOTE_SYNC_PRECHECK.json',
        })
        self.assertEqual(len(root_names), 6)
        flat = self.root / 'flat-download'
        flat.mkdir()
        for name in (
                'artifacts/ephem-phase3-linux-arm64.tar.gz', 'SHA256SUMS.txt',
                'RELEASE_ALIGNMENT.json', 'REMOTE_SYNC_PRECHECK.json',
                'DOWNLOAD_SHA256SUMS.txt'):
            shutil.copy2(stage / name, flat / Path(name).name)
        download_names = self.assert_checksums(
            (flat / 'DOWNLOAD_SHA256SUMS.txt').read_bytes(),
            lambda name: (flat / name).read_bytes(),
        )
        self.assertEqual(download_names, {
            'ephem-phase3-linux-arm64.tar.gz', 'SHA256SUMS.txt',
            'RELEASE_ALIGNMENT.json', 'REMOTE_SYNC_PRECHECK.json',
        })
        self.assertTrue(all('/' not in name for name in download_names))
        self.assertNotIn('DOWNLOAD_SHA256SUMS.txt', stage_names)
        self.assertEqual((stage / 'RELEASE_ALIGNMENT.json').read_bytes(), self.frozen[FROZEN[3]])
        self.assertEqual((stage / 'REMOTE_SYNC_PRECHECK.json').read_bytes(), self.precheck)
        self.assertIn('latency gate: FAIL', result.stdout)
        with tarfile.open(stage / 'artifacts/ephem-phase3-linux-arm64.tar.gz') as archive:
            names = set(archive.getnames())
            read = lambda name: archive.extractfile(name).read()
            payload_names = self.assert_checksums(read('SHA256SUMS.txt'), read)
            self.assertEqual(names, payload_names | {'SHA256SUMS.txt'})
            manifest = json.loads(read('RELEASE_BUNDLE.json'))
            self.assertEqual(manifest['title'],
                             'v0.3.0-stateful-alpha: 0.52ms Stateful COW Runtime & Zero-Persistence Ledger')
            self.assertEqual(manifest['historical_alignment']['native_p95_ms'], 0.520076)
            self.assertEqual(read(PRECHECK), self.precheck)
            self.assertEqual(manifest['remote_sync_precheck']['path'], PRECHECK)
            exceptions = manifest['source_metadata_exceptions']
            self.assertEqual(len(exceptions), 1)
            self.assertEqual(exceptions[0]['path'], 'Cargo.lock')
            self.assertEqual(exceptions[0]['allowed_change'],
                             'Exactly one ephem-gate package version: 0.1.0 -> 0.2.0')
            for directory in ('release-alignment-final', 'release-alignment-run1',
                              'release-alignment-run3', 'measured-workspace',
                              'remote-sync-run'):
                expected = {
                    path.relative_to(self.root).as_posix()
                    for path in (self.root / 'reports/phase3' / directory).rglob('*')
                    if path.is_file()
                }
                self.assertTrue(expected)
                self.assertTrue(expected <= names, expected - names)
            for name, original in self.frozen.items():
                self.assertEqual(read(name), original)
            for name, record in manifest['files'].items():
                self.assertEqual(hashlib.sha256(read(name)).hexdigest(), record['sha256'])
                self.assertEqual(len(read(name)), record['bytes'])
        before = (self.root / 'SHA256SUMS.txt').read_bytes()
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'SHA256SUMS.txt').read_bytes(), before)
        for name, original in self.frozen.items():
            self.assertEqual((self.root / name).read_bytes(), original)

    def test_other_lockfile_changes_are_rejected(self):
        lock = self.root / 'Cargo.lock'
        lock.write_bytes(lock.read_bytes() + b'\n')
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recorded provenance mismatch: Cargo.lock', result.stderr)
        self.assertFalse((self.root / 'SHA256SUMS.txt').exists())

    def with_x86_addendum(self):
        """Use published ARM64 bytes without executing any ELF or fixture worker."""
        stage = self.root / STAGE
        for name in BASE_FILES:
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / STAGE / name, destination)
        # The legacy fixture substitutes a precheck; the additive path instead
        # preserves the already published precheck and notes byte for byte.
        (self.root / PRECHECK).write_bytes((stage / 'REMOTE_SYNC_PRECHECK.json').read_bytes())
        (self.root / 'docs/EPHEM_PHASE3.md').write_bytes((stage / 'docs/EPHEM_PHASE3.md').read_bytes())
        self.assertEqual(hashlib.sha256((stage / ARM64).read_bytes()).hexdigest(), ARM64_SHA256)
        sums = ''.join(f'{hashlib.sha256((stage / name).read_bytes()).hexdigest()}  {name}\n'
                       for name in sorted(BASE_FILES)).encode()
        (stage / 'SHA256SUMS.txt').write_bytes(sums)
        downloads = ''.join(
            f'{hashlib.sha256((stage / name).read_bytes()).hexdigest()}  {Path(name).name}\n'
            for name in DOWNLOAD_FILES).encode()
        (stage / 'DOWNLOAD_SHA256SUMS.txt').write_bytes(downloads)
        for directory in (X86_DIRECTORY, 'docs/audit'):
            shutil.copytree(ROOT / directory, self.root / directory,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in ('README.md', '.github/workflows/ci.yml',
                     'scripts/verify_x86_evidence.py', 'scripts/verify_stored_evidence.py',
                     'tests/test_x86_evidence.py', 'tests/test_stored_evidence.py',
                     'tests/test_phase3_release_bundle.py'):
            if (ROOT / name).exists():
                destination = self.root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, destination)
        root_sums = ''.join(
            f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.root).as_posix()}\n'
            for path in sorted(stage.rglob('*')) if path.is_file()).encode()
        (self.root / 'SHA256SUMS.txt').write_bytes(root_sums)
        return stage, {name: (stage / name).read_bytes() for name in BASE_FILES}

    def test_x86_addendum_preserves_arm64_and_all_checksum_layers_repeatably(self):
        stage, originals = self.with_x86_addendum()
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('gh release upload v0.3.0-stateful-alpha', result.stdout)
        self.assertIn(X86 + ' SHA256SUMS.txt DOWNLOAD_SHA256SUMS.txt --clobber', result.stdout)
        for name, content in originals.items():
            self.assertEqual((stage / name).read_bytes(), content)
        stage_names = self.assert_checksums((stage / 'SHA256SUMS.txt').read_bytes(),
                                            lambda name: (stage / name).read_bytes())
        self.assertEqual(stage_names, set(BASE_FILES) | {X86})
        flat = self.root / 'flat-download'
        flat.mkdir()
        for name in (*DOWNLOAD_FILES, X86, 'DOWNLOAD_SHA256SUMS.txt'):
            shutil.copy2(stage / name, flat / Path(name).name)
        download_names = self.assert_checksums((flat / 'DOWNLOAD_SHA256SUMS.txt').read_bytes(),
                                               lambda name: (flat / name).read_bytes())
        self.assertEqual(download_names, {Path(name).name for name in (*DOWNLOAD_FILES, X86)})
        with tarfile.open(stage / X86) as archive:
            names = set(archive.getnames())
            read = lambda name: archive.extractfile(name).read()
            evidence_files = {path.name for path in (self.root / X86_DIRECTORY).iterdir()}
            self.assertEqual(len(evidence_files), 8)
            self.assertEqual(names, evidence_files | {'SHA256SUMS.txt'})
            self.assertEqual(self.assert_checksums(read('SHA256SUMS.txt'), read), evidence_files)
            for name in evidence_files:
                self.assertEqual(read(name), (self.root / X86_DIRECTORY / name).read_bytes())
            for member in archive.getmembers():
                self.assertEqual((member.mtime, member.uid, member.gid, member.mode), (0, 0, 0, 0o644))
        root_names = self.assert_checksums((self.root / 'SHA256SUMS.txt').read_bytes(),
                                           lambda name: (self.root / name).read_bytes())
        required = {path.relative_to(self.root).as_posix()
                    for directory in (X86_DIRECTORY, 'docs/audit')
                    for path in (self.root / directory).rglob('*') if path.is_file()}
        self.assertTrue(required <= root_names)
        self.assertTrue({'scripts/bundle_release.sh', 'scripts/verify_x86_evidence.py',
                         'scripts/verify_stored_evidence.py', 'README.md',
                         'tests/test_phase3_release_bundle.py'} <= root_names)
        before = (self.root / 'SHA256SUMS.txt').read_bytes()
        archive_before = (stage / X86).read_bytes()
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((stage / X86).read_bytes(), archive_before)
        self.assertEqual((self.root / 'SHA256SUMS.txt').read_bytes(), before)
        result = self.bundle('--output', 'artifacts/release-phase3/ci')
        self.assertEqual(result.returncode, 0, result.stderr)
        ci = self.root / 'artifacts/release-phase3/ci'
        self.assertEqual((ci / ARM64).read_bytes(), originals[ARM64])
        self.assertEqual((ci / X86).read_bytes(), archive_before)

    def test_corrupt_x86_evidence_cannot_modify_published_assets(self):
        stage, originals = self.with_x86_addendum()
        before = (self.root / 'SHA256SUMS.txt').read_bytes()
        report = self.root / X86_DIRECTORY / 'warm-native.json'
        report.write_bytes(report.read_bytes() + b'\n')
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('x86 stored-evidence verification failed', result.stderr)
        self.assertFalse((stage / X86).exists())
        self.assertEqual((self.root / 'SHA256SUMS.txt').read_bytes(), before)
        for name, content in originals.items():
            self.assertEqual((stage / name).read_bytes(), content)

    def test_arm64_archive_drift_is_rejected_by_published_identity(self):
        stage, _ = self.with_x86_addendum()
        archive = stage / ARM64
        archive.write_bytes(archive.read_bytes() + b'\n')
        before = (self.root / 'SHA256SUMS.txt').read_bytes()
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('published ARM64 archive identity differs', result.stderr)
        self.assertFalse((stage / X86).exists())
        self.assertEqual((self.root / 'SHA256SUMS.txt').read_bytes(), before)

    def test_measured_snapshot_hash_must_match_frozen_provenance(self):
        snapshot = self.root / 'reports/phase3/measured-workspace/Cargo.lock'
        snapshot.write_bytes(snapshot.read_bytes() + b'\n')
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('recorded provenance mismatch: reports/phase3/measured-workspace/Cargo.lock',
                      result.stderr)
        self.assertFalse((self.root / 'SHA256SUMS.txt').exists())


if __name__ == '__main__':
    unittest.main()
