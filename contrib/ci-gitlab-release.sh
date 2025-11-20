#!/usr/bin/env sh

FILE_NAMES="${1:-}"
if [ -z "$FILE_NAMES" ]; then
  echo "Error: FILE_NAMES argument is required" >&2
  exit 1
fi

if [ -z "${CI_COMMIT_TAG:-}" ]; then
  echo "Error: CI_COMMIT_TAG is not set" >&2
  exit 1
fi

if [ -z "${GITLAB_RELEASE_TOKEN:-}" ]; then
  echo "Error: GITLAB_RELEASE_TOKEN is required" >&2
  exit 1
fi

glab auth login --token "${GITLAB_RELEASE_TOKEN}"
glab release create "${CI_COMMIT_TAG}" ${FILE_NAMES} \
	--repo ark-bitcoin/bark \
	--use-package-registry \
	--notes "Automated release ${CI_COMMIT_TAG} from Woodpecker CI"

echo "GitLab release: https://gitlab.com/ark-bitcoin/bark/-/releases/${CI_COMMIT_TAG}"
