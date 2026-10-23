#!/usr/bin/env bash
set -euo pipefail

# Issue publication is explicit. The default only renders shell-quoted commands.
repository='testofschool/ephem'
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
seed_dir="$repository_root/.github/ISSUE_SEEDS"

usage() {
    cat <<'USAGE'
Usage: scripts/seed_issues.sh [--dry-run | --post]

Default / --dry-run: validate all three seeds and print gh issue create commands.
--post: explicitly publish missing issues to testofschool/ephem using gh.
        Requires the requested repository labels to exist before publication.
        An existing open or closed issue with the exact title is skipped.

Review .github/ISSUE_SEEDS/*.md before opting into --post. Posting requires an
authenticated GitHub CLI and Python 3. Dry-run needs neither and makes no API calls.
Duplicate detection is best effort; do not run simultaneous --post invocations.
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

mode='--dry-run'
if (( $# > 1 )); then
    usage >&2
    exit 2
fi
if (( $# == 1 )); then
    case "$1" in
        --dry-run|--post) mode=$1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
fi

seed_files=(
    issue_1_bpf_lsm.md
    issue_2_hybrid_atomicity.md
    issue_3_x86_parity.md
)
# Parallel label arrays keep labels with spaces intact, including "help wanted".
primary_labels=(enhancement rfc benchmarks)
secondary_labels=(kernel architecture 'help wanted')
titles=()
body_files=()

# Validate the entire input set before rendering commands or making API calls.
for seed_name in "${seed_files[@]}"; do
    body_file="$seed_dir/$seed_name"
    [[ -f "$body_file" && -r "$body_file" && -s "$body_file" ]] ||
        die "missing, empty, or unreadable issue seed: $body_file"
    IFS= read -r heading < "$body_file" || die "cannot read issue title: $body_file"
    [[ "$heading" == '# '* && "$heading" != '# ' ]] ||
        die "first line must be '# <issue title>': $body_file"
    titles+=("${heading#\# }")
    body_files+=("$body_file")
done

if [[ "$mode" == '--dry-run' ]]; then
    printf 'DRY RUN: no GitHub requests made. Review the seeds, then use --post.\n'
    for index in "${!seed_files[@]}"; do
        printf 'gh issue create --repo %q --title %q --body-file %q --label %q --label %q\n' \
            "$repository" "${titles[$index]}" "${body_files[$index]}" \
            "${primary_labels[$index]}" "${secondary_labels[$index]}"
    done
    exit 0
fi

command -v gh >/dev/null 2>&1 || die '--post requires the GitHub CLI (gh)'
command -v python3 >/dev/null 2>&1 || die '--post requires Python 3 for exact-title matching'
gh auth status --hostname github.com >/dev/null 2>&1 ||
    die 'GitHub CLI authentication is unavailable for github.com; run gh auth login first'

# Validate all labels before the first issue mutation. Missing labels require a
# deliberate repository setup step rather than publishing partially labeled RFCs.
gh label list --repo "$repository" --limit 1000 --json name |
    python3 -c '
import json
import sys

labels = json.load(sys.stdin)
if not isinstance(labels, list) or any(
    not isinstance(label, dict) or not isinstance(label.get("name"), str)
    for label in labels
):
    raise SystemExit("malformed repository label response")
existing = {label["name"] for label in labels}
missing = sorted(set(sys.argv[1:]) - existing)
if missing:
    raise SystemExit("required repository labels are missing: " + ", ".join(missing))
' "${primary_labels[@]}" "${secondary_labels[@]}" ||
    die 'cannot validate requested repository labels; no issues were created'

for index in "${!seed_files[@]}"; do
    title=${titles[$index]}
    # Search all states, then compare the actual title rather than trusting
    # GitHub search token matching. A list/API/JSON error aborts before creation.
    existing=$(gh issue list --repo "$repository" --state all \
        --search "\"$title\" in:title" --limit 1000 --json title,url |
        python3 -c '
import json
import sys

issues = json.load(sys.stdin)
if not isinstance(issues, list):
    raise SystemExit("issue list response is not a JSON list")
for issue in issues:
    if not isinstance(issue, dict) or not isinstance(issue.get("title"), str) or not isinstance(issue.get("url"), str):
        raise SystemExit("malformed issue list response")
for issue in issues:
    if issue["title"] == sys.argv[1]:
        print(issue["url"])
' "$title") || die "cannot check existing issues for: $title"
    if [[ -n "$existing" ]]; then
        printf 'SKIP existing issue: %s\n%s\n' "$title" "$existing"
        continue
    fi
    # Do not automatically retry an ambiguous create failure: it may have posted.
    gh issue create --repo "$repository" --title "$title" \
        --body-file "${body_files[$index]}" \
        --label "${primary_labels[$index]}" --label "${secondary_labels[$index]}" ||
        die "issue creation failed for: $title; inspect GitHub before retrying"
done
