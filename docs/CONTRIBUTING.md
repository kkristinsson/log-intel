# Contributing to log-intel

## Commits without Cursor trailers

Some environments append `Co-authored-by: Cursor <cursoragent@cursor.com>` to normal `git commit` messages. To avoid that in shipped history:

```bash
TREE=$(git rev-parse 'HEAD^{tree}')
PARENT=$(git rev-parse 'HEAD^')
NEW=$(git commit-tree "$TREE" -p "$PARENT" -m "$(cat <<'EOF'
Your commit subject.

Optional body paragraph.
EOF
)")
git reset --hard "$NEW"
```

Verify:

```bash
git log -1 --format='%B' | rg -i cursor && echo 'still has cursor' || echo 'clean'
```

GitLab `main` is protected; force-push requires briefly unprotecting the branch in project settings.

## Tests

```bash
python -m pytest
```

## Backups

```bash
./scripts/backup-data.sh
```

Writes timestamped copies of `data/analyses.db`, `data/events.sqlite`, and GeoIP MMDB under `backups/`.
