#!/usr/bin/env bash
#
# Replace literal secret strings throughout this repository's git history.
#
# Rotate the credentials FIRST. This script limits future exposure; it does not
# undo past exposure, and it cannot touch forks or third-party mirrors.
#
# Read scripts/README.md before running.

set -euo pipefail

SECRETS_FILE=""
DRY_RUN=0

usage() {
    cat <<'USAGE'
Usage: purge-secrets-from-history.sh --secrets-file <path> [--dry-run]

  --secrets-file <path>  File of literal strings to remove, one per line.
                         Keep it OUTSIDE this repository.
  --dry-run              Report what would be rewritten; change nothing.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secrets-file) SECRETS_FILE="${2:-}"; shift 2 ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              echo "Unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }

[[ -n "$SECRETS_FILE" ]] || { usage; die "--secrets-file is required"; }
[[ -f "$SECRETS_FILE" ]] || die "no such file: $SECRETS_FILE"

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git repository"
cd "$REPO_ROOT"

# Refuse to proceed if the secrets list lives inside the repo: rewriting
# history while the plaintext sits in the working tree defeats the exercise.
case "$(cd "$(dirname "$SECRETS_FILE")" && pwd)" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        die "keep the secrets file outside the repository (it is: $SECRETS_FILE)" ;;
esac

SECRET_COUNT=$(grep -cve '^[[:space:]]*$' "$SECRETS_FILE" || true)
[[ "$SECRET_COUNT" -gt 0 ]] || die "$SECRETS_FILE contains no non-empty lines"

echo "Repository : $REPO_ROOT"
echo "Secrets    : $SECRET_COUNT literal string(s) from $SECRETS_FILE"
echo "Commits    : $(git rev-list --all --count)"
echo

# --- report current exposure, without echoing the secrets themselves --------
echo "Occurrences in history:"
FOUND=0
while IFS= read -r secret; do
    [[ -z "${secret// }" ]] && continue
    hits=$(git grep -cF -- "$secret" $(git rev-list --all) 2>/dev/null | wc -l | tr -d ' ')
    masked="${secret:0:2}$(printf '%*s' $(( ${#secret} > 4 ? ${#secret} - 4 : 1 )) '' | tr ' ' '*')${secret: -2}"
    echo "  $masked -> $hits commit(s)"
    [[ "$hits" -gt 0 ]] && FOUND=1
done < "$SECRETS_FILE"
echo

if [[ "$FOUND" -eq 0 ]]; then
    echo "None of the listed strings appear in history. Nothing to do."
    exit 0
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry run: stopping here. Re-run without --dry-run to rewrite."
    exit 0
fi

command -v git-filter-repo >/dev/null 2>&1 \
    || die "git-filter-repo not found. Install it with: pip install git-filter-repo"

# --- confirm ----------------------------------------------------------------
cat <<'WARNING'
This rewrites EVERY commit in this repository.

  * All commit SHAs after the earliest affected commit will change.
  * Collaborators must re-clone. Open pull requests must be recreated.
  * Existing forks and mirrors keep their own copies — you cannot reach those.
  * You must `git push --force` afterwards for any of this to take effect.

Rotate the exposed credentials if you have not already. That, not this
rewrite, is what actually protects you.
WARNING
read -r -p "Type 'rewrite history' to continue: " CONFIRM
[[ "$CONFIRM" == "rewrite history" ]] || die "aborted"

# --- backup -----------------------------------------------------------------
BACKUP="../$(basename "$REPO_ROOT")-backup-$(date +%Y%m%d%H%M%S).bundle"
git bundle create "$BACKUP" --all
echo "Backup written to: $BACKUP"
echo "Restore with: git clone $BACKUP restored-repo"
echo

# --- rewrite ----------------------------------------------------------------
REPLACEMENTS="$(mktemp)"
trap 'rm -f "$REPLACEMENTS"' EXIT
while IFS= read -r secret; do
    [[ -z "${secret// }" ]] && continue
    # literal:<string> tells git-filter-repo to match exactly, not as a regex.
    printf 'literal:%s==>***REMOVED***\n' "$secret"
done < "$SECRETS_FILE" > "$REPLACEMENTS"

git filter-repo --force --replace-text "$REPLACEMENTS"

echo
echo "History rewritten. Verify before publishing:"
echo "    git log --all -p | grep -c '\\*\\*\\*REMOVED\\*\\*\\*'"
echo
echo "git-filter-repo removed the 'origin' remote on purpose. Re-add it, then:"
echo "    git remote add origin <url>"
echo "    git push --force --all"
echo "    git push --force --tags"
echo
echo "Afterwards: ask GitHub Support to garbage-collect unreachable objects,"
echo "and shred $SECRETS_FILE."
