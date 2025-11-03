#!/usr/bin/env sh

if [ -z "${CI_COMMIT_SHA}" ]; then
	exit 1
fi

DEST_FOLDER="/host/data/test/${CI_COMMIT_SHA}/"
KEEP_FILE="/host/data/test/${CI_COMMIT_SHA}/.keep"

if [ ! -f "${KEEP_FILE}" ]; then
  rm -rf "${DEST_FOLDER}" || true
fi