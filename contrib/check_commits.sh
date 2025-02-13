#!/bin/bash
set -e

BASE_BRANCH="origin/master"

BRANCH_COMMIT=$(git rev-parse HEAD)
echo "Branch commit: ${BRANCH_COMMIT}"

git fetch --prune origin "+refs/heads/*:refs/remotes/origin/*"

FEATURE_BRANCH=$(git branch -r --contains "${BRANCH_COMMIT}" --sort=-committerdate)
echo "Running checks for branch: $FEATURE_BRANCH"

BASE_COMMIT=$(git merge-base $BASE_BRANCH ${FEATURE_BRANCH})
echo "Branch base commit: $BASE_COMMIT"

COMMITS=$(git log --oneline --reverse ${BASE_COMMIT}..${FEATURE_BRANCH})

# Loop through each commit
while IFS= read -r COMMIT; do
  echo "Commit found: $COMMIT"
  # Get the commit hash and message
  COMMIT_HASH=$(echo "$COMMIT" | awk '{print $1}')
  COMMIT_MSG=$(echo "$COMMIT" | sed 's/^[a-f0-9]* //')
  echo "Parsed commit $COMMIT_HASH: $COMMIT_MSG"

  echo "Running checks for commit ${COMMIT_HASH}: ${COMMIT_MSG}"
  git checkout ${COMMIT_HASH}
  just prechecks

  if [[ "${COMMIT_MSG}" == BROKEN:* ]]; then
    echo "Skipping commit hash ${COMMIT_HASH} (due to commit message prefix) \"${COMMIT_MSG}\""
  else
    just check
  fi
done <<< "$COMMITS"
