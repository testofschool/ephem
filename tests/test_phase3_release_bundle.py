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

    def bundle(self):
        return subprocess.run(
            ['bash', 'scripts/bundle_release.sh'], cwd=self.root,
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
