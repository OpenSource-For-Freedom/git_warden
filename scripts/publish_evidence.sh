#!/usr/bin/env bash
# Commit and push the evidence store (plus any extra paths) to the current branch.
#
#   scripts/publish_evidence.sh "<commit message>" "<regenerate command>" [extra paths...]
#
# The run may take a while, so main can move (or a person may have edited
# evidence/findings.csv by hand). We rebase onto the live tip before pushing.
# A conflict inside evidence/ is resolved by keeping the upstream file (with the
# hand edits) and re-running the regenerate command, which refreshes generated
# columns and preserves the editable ones. Any other conflict stops the push.
set -euo pipefail
msg="$1"; regen="$2"; shift 2
branch="${GITHUB_REF_NAME:?}"

git config user.name "git-warden[bot]"
git config user.email "git-warden@users.noreply.github.com"
git add evidence "$@" 2>/dev/null || git add evidence
if git diff --cached --quiet; then
  echo "evidence unchanged; nothing to push."
  exit 0
fi
git commit -q -m "$msg [skip ci]"

for attempt in 1 2 3 4 5; do
  git fetch -q origin "$branch"
  if ! git rebase "origin/$branch"; then
    conflicted=$(git diff --name-only --diff-filter=U)
    if echo "$conflicted" | grep -qv '^evidence/'; then
      git rebase --abort || true
      echo "::error::rebase conflict outside evidence/: $conflicted"
      exit 1
    fi
    # During a rebase "ours" is the upstream tip: keep it, then regenerate.
    echo "$conflicted" | xargs git checkout --ours --
    eval "$regen"
    git add evidence
    GIT_EDITOR=true git rebase --continue
  fi
  if git push -q origin HEAD:"$branch"; then
    echo "evidence pushed (attempt $attempt)."
    exit 0
  fi
  echo "push raced with another update; retrying (attempt $attempt)."
done
echo "::error::could not push evidence after 5 attempts."
exit 1
