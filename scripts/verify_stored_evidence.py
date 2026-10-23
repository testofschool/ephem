#!/usr/bin/env python3
"""Check the preserved 2026-10-23 four-report snapshot in this repository.

The original gate and its manifest pin are preserved unchanged under docs/audit.
This wrapper supplies repository paths; --root and --manifest can override them.
Passing checks stored records only and does not reexecute the EPHEM runtime.
"""

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "audit" / "stored-evidence-20261023"


def main(argv=None):
    spec = importlib.util.spec_from_file_location(
        "ephem_stored_evidence_20261023", SNAPSHOT / "verify_stored_evidence.py"
    )
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate.main([
        "--root", str(ROOT),
        "--manifest", str(SNAPSHOT / "evidence_manifest.json"),
        *(sys.argv[1:] if argv is None else argv),
    ])


if __name__ == "__main__":
    sys.exit(main())
