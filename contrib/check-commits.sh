#!/usr/bin/env sh
set -e

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

run_checks() {
	COMMIT_MSG=$(git log --oneline -1 | sed 's/^[a-f0-9]* //')

	just prechecks

	case "${COMMIT_MSG}" in
		BROKEN:*)
			log_info "Skipping cargo check (due to commit message prefix) \"${COMMIT_MSG}\""
			;;
		*)
			just check
			;;
	esac
}

# Trying to find the base branch named master either from origin or locally
MASTER_BRANCH="origin/master"
if git ls-remote --heads "origin" "master" | grep -q "master"; then
	log_info "origin/master branch found"
elif git show-ref --verify --quiet refs/heads/master; then
	log_info "local master branch found"
	MASTER_BRANCH="master"
else
	log_error "No master branch found"
fi

# Trying to find the feature branch tip
if [ -z "$CI_COMMIT_SOURCE_BRANCH" ]; then
	if [ -z "$CI_COMMIT_SHA" ]; then
		log_info "Not running in CI context, using current git hash"
		FEATURE_BRANCH=$(git rev-parse HEAD)
	else
		log_info "No source branch found, using CI commit hash"
		FEATURE_BRANCH="${CI_COMMIT_SHA}"
	fi
else
	if git ls-remote --heads "origin" ${CI_COMMIT_SOURCE_BRANCH} | grep -q "${CI_COMMIT_SOURCE_BRANCH}"; then
		log_info "remote feature branch found"
		FEATURE_BRANCH="origin/${CI_COMMIT_SOURCE_BRANCH}"
	elif git show-ref --verify --quiet refs/heads/${CI_COMMIT_SOURCE_BRANCH}; then
		log_info "local feature branch found"
		FEATURE_BRANCH="${CI_COMMIT_SOURCE_BRANCH}"
	else
		log_info "Could not find source branch in remote or local - likely a fork. Falling back to commit SHA."
		FEATURE_BRANCH="${CI_COMMIT_SHA}"
	fi
fi

git fetch --prune origin "+refs/heads/*:refs/remotes/origin/*"

# Find where the feature branch diverged from master
BASE_COMMIT=$(git merge-base ${MASTER_BRANCH} ${FEATURE_BRANCH})
if [ -z "$BASE_COMMIT" ]; then
	log_error "Could not determine base commit between ${MASTER_BRANCH} and ${FEATURE_BRANCH}"
fi
log_info "Branch base commit: ${BASE_COMMIT}"

# List all commits from fork point to branch tip, in order
COMMITS=$(git log --oneline --reverse ${BASE_COMMIT}..${FEATURE_BRANCH})
if [ -z "$COMMITS" ]; then
	log_info "No commits found between ${BASE_COMMIT} and ${FEATURE_BRANCH}."
	run_checks
	exit 0
fi

ORIGINAL_HEAD=$(git symbolic-ref -q HEAD || git rev-parse HEAD)

# Check out and verify each commit individually
echo "$COMMITS" | while IFS= read -r COMMIT; do
	COMMIT_HASH=$(echo "$COMMIT" | awk '{print $1}')
	log_info "Checking commit: $COMMIT"
	git checkout -f ${COMMIT_HASH}
	run_checks
done

git checkout -f ${ORIGINAL_HEAD}
