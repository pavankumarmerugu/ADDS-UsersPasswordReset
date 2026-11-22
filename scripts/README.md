# scripts

## `purge-secrets-from-history.sh`

Rewrites every commit in this repository, replacing literal secret strings with
`***REMOVED***`.

### Read this first

- **Rotate the credentials before you run this.** Purging does not un-publish
  anything. The repository is public: assume the values were cloned, mirrored
  and indexed years ago. Rotation is the control; purging is hygiene.
- **Every commit SHA changes.** Collaborators must re-clone. Open pull requests
  must be recreated. Tags move.
- **Existing forks keep their own copies.** You cannot rewrite someone else's
  fork. Ask GitHub Support to garbage-collect the upstream repository's
  unreachable objects after you force-push.

### Usage

```bash
pip install git-filter-repo

# 1. List the literal strings to remove — one per line.
#    This file is git-ignored. Do not commit it.
cat > /tmp/secrets-to-purge.txt <<'EOF'
<the service account password>
<the service account username>
<the internal IP address>
EOF

# 2. Dry run: show what would change, touch nothing.
./scripts/purge-secrets-from-history.sh --secrets-file /tmp/secrets-to-purge.txt --dry-run

# 3. Rewrite history locally. Takes a backup bundle first.
./scripts/purge-secrets-from-history.sh --secrets-file /tmp/secrets-to-purge.txt

# 4. Verify, then publish. This is the irreversible step.
git log --all -p | grep -c '<a secret fragment>'   # expect 0
git push --force --all
git push --force --tags

# 5. Shred the list.
shred -u /tmp/secrets-to-purge.txt   # or: rm -P on macOS
```

The script never writes the secrets into the repository — that is the whole
reason it reads them from a file outside it.

### If you would rather start clean

For a repository this small, the alternative is defensible: create a fresh
repository with no history, push version 2.0.0 as its initial commit, and
archive the old one. You lose the history; you also lose every way of
reconstructing it.
