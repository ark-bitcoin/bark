#!/usr/bin/env sh

if [ -z "${TEST_DIRECTORY}" ]; then
	exit 1
fi
if [ -z "${CI_COMMIT_SHA}" ]; then
	exit 1
fi

SOURCE_FOLDER="$(pwd)/${TEST_DIRECTORY#./}"
DEST_FOLDER="/host/data/test/${CI_COMMIT_SHA}/"

mkdir -p "${DEST_FOLDER}"
cp -r "${SOURCE_FOLDER}" "${DEST_FOLDER}"
echo "Test data -> https://ci.2nd.dev/testdata/${CI_COMMIT_SHA}/"
