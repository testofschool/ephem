"""Issue publication contract checks using a local gh double; no network calls."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/seed_issues.sh"
LABELS = (("enhancement", "kernel"), ("rfc", "architecture"),
          ("benchmarks", "help wanted"))
SEEDS = ("issue_1_bpf_lsm.md", "issue_2_hybrid_atomicity.md", "issue_3_x86_parity.md")
TITLES = tuple((ROOT / ".github/ISSUE_SEEDS" / seed).read_text().splitlines()[0][2:]
               for seed in SEEDS)

MOCK_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["MOCK_GH_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
if args[:2] == ["auth", "status"]:
    raise SystemExit(0)
if args[:2] == ["label", "list"]:
    if os.environ.get("MOCK_LABEL_API_FAIL"):
        raise SystemExit(17)
    labels = ["enhancement", "kernel", "rfc", "architecture", "benchmarks", "help wanted"]
    if os.environ.get("MOCK_MISSING_LABEL"):
        labels.remove("architecture")
    print(json.dumps([{"name": label} for label in labels]))
elif args[:2] == ["issue", "list"]:
    if os.environ.get("MOCK_ISSUE_API_FAIL"):
        raise SystemExit(19)
    title = args[args.index("--search") + 1][1:-len('" in:title')]
    issues = []
    if os.environ.get("MOCK_EXISTING") and title.startswith("[Kernel/LSM]"):
        issues.append({"title": title, "url": "https://github.com/testofschool/ephem/issues/12"})
    # A search match with an inexact title must not suppress creation.
    issues.append({"title": title + " follow-up", "url": "https://github.com/testofschool/ephem/issues/13"})
    print(json.dumps(issues))
elif args[:2] == ["issue", "create"]:
    print("https://github.com/testofschool/ephem/issues/99")
else:
    raise SystemExit("unexpected mock gh call: " + repr(args))
'''


class IssueSeedingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ephem-issue-test-")
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        mock = self.temp_path / "gh"
        mock.write_text(MOCK_GH)
        mock.chmod(0o755)
        self.log = self.temp_path / "gh-calls.jsonl"
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.temp_path) + os.pathsep + self.env["PATH"],
                        MOCK_GH_LOG=str(self.log))
        for name in ("MOCK_LABEL_API_FAIL", "MOCK_ISSUE_API_FAIL",
                     "MOCK_MISSING_LABEL", "MOCK_EXISTING"):
            self.env.pop(name, None)

    def run_script(self, *args, **overrides):
        return subprocess.run(["bash", str(SCRIPT), *args], cwd=ROOT,
                              env=dict(self.env, **overrides), text=True,
                              capture_output=True)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def assert_labels(self, command, expected):
        actual = [command[i + 1] for i, arg in enumerate(command) if arg == "--label"]
        self.assertEqual(actual, list(expected))

    def test_dry_run_renders_exact_labels_without_invoking_gh(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        commands = [shlex.split(line) for line in result.stdout.splitlines()[1:]]
        self.assertEqual(len(commands), 3)
        for command, title, labels in zip(commands, TITLES, LABELS):
            self.assertEqual(command[:3], ["gh", "issue", "create"])
            self.assertEqual(command[command.index("--title") + 1], title)
            self.assert_labels(command, labels)

    def test_post_passes_exact_labels_to_all_three_creates(self):
        result = self.run_script("--post")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(calls[1][:2], ["label", "list"])
        creates = [call for call in calls if call[:2] == ["issue", "create"]]
        self.assertEqual(len(creates), 3)
        for command, title, labels in zip(creates, TITLES, LABELS):
            self.assertEqual(command[command.index("--title") + 1], title)
            self.assert_labels(command, labels)

    def test_existing_exact_title_is_skipped(self):
        result = self.run_script("--post", MOCK_EXISTING="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        creates = [call for call in self.calls() if call[:2] == ["issue", "create"]]
        self.assertEqual(len(creates), 2)
        self.assertIn("SKIP existing issue: " + TITLES[0], result.stdout)
        self.assertIn("/issues/12", result.stdout)

    def test_issue_api_failure_does_not_create(self):
        result = self.run_script("--post", MOCK_ISSUE_API_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot check existing issues", result.stderr)
        self.assertFalse(any(call[:2] == ["issue", "create"] for call in self.calls()))

    def test_missing_label_aborts_before_issue_mutation(self):
        result = self.run_script("--post", MOCK_MISSING_LABEL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("architecture", result.stderr)
        self.assertEqual(len(self.calls()), 2)

    def test_label_api_failure_aborts_before_issue_mutation(self):
        result = self.run_script("--post", MOCK_LABEL_API_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot validate requested repository labels", result.stderr)
        self.assertEqual(len(self.calls()), 2)


if __name__ == "__main__":
    unittest.main()
