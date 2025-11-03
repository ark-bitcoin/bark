#!/usr/bin/env sh
set -e

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

parse_commit() {
	COMMIT_HASH=$(echo "$1" | awk '{print $1}')
	COMMIT_MSG=$(echo "$1" | sed 's/^[a-f0-9]* //')

	log_info "Commit found: $COMMIT, Parsed into $COMMIT_HASH: $COMMIT_MSG"
}

run_checks() {
	just prechecks

	case "${COMMIT_MSG}" in
		BROKEN:*)
			log_info "Skipping commit hash ${COMMIT_HASH} (due to commit message prefix) \"${COMMIT_MSG}\""
			;;
		*)
			just check
			;;
	esac
}

CI_CONTEXT=true
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

# Trying to find the branch that we want to merge in either using either CI env. vars or HEAD commit hash
if [ -z "$CI_COMMIT_SOURCE_BRANCH" ]; then
	if [ -z "$CI_COMMIT_SHA" ]; then
		log_info "Not running in CI context so assuming local development and using current git hash"
		FEATURE_BRANCH=$(git rev-parse HEAD)
		CI_CONTEXT=false
	else
		log_info "No source branch found using CI commit hash"
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

log_info "Rebasing: ${FEATURE_BRANCH} into ${MASTER_BRANCH}"

if [ "$CI_CONTEXT" = "true" ]; then
	git fetch --prune origin "+refs/heads/*:refs/remotes/origin/*"
	git config --global user.email "ci@gitlab.com"
	git config --global user.name "ci"
fi

# Trying to find where the feature branch branched away from master
BASE_COMMIT=$(git merge-base ${MASTER_BRANCH} ${FEATURE_BRANCH})
if [ -z "$BASE_COMMIT" ]; then
	log_error "Could not determine base commit between ${MASTER_BRANCH} and ${FEATURE_BRANCH}"
fi
log_info "Branch base commit: ${BASE_COMMIT}"

# Listing all commits from the branch until the point it branched off from in the order they were committed
COMMITS=$(git log --oneline --reverse ${BASE_COMMIT}..${FEATURE_BRANCH})
if [ -z "$COMMITS" ]; then
	log_info "No commits found between ${BASE_COMMIT} and ${FEATURE_BRANCH}."

	run_checks

	exit 0
fi

# Checkout the master branch
git checkout -f ${MASTER_BRANCH}

# Attempt to cherry pick all commits from the branch one by one
echo "$COMMITS" | while IFS= read -r COMMIT; do
	parse_commit "$COMMIT"

	if git cherry-pick ${COMMIT_HASH}; then
		run_checks
	else
		git cherry-pick --abort || echo "Ignoring cherry pick abort failure."
		log_info "Cherry pick failure for commit $COMMIT_HASH"
		echo "true" > CHERRY_PICK_FAILURE

		break
	fi
done

if [ -r CHERRY_PICK_FAILURE ] && [ "$(cat CHERRY_PICK_FAILURE)" = "true" ]; then
	log_info "Cherry-picking failed, running alternative workflow using ${BASE_COMMIT}..."

	echo "$COMMITS" | while IFS= read -r COMMIT; do
		parse_commit "$COMMIT"

		git checkout -f ${COMMIT_HASH}

		run_checks
	done
fi