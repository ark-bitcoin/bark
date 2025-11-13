#!/usr/bin/env sh

if [ -z "${TEST_DIRECTORY}" ]; then
	exit 1
fi
if [ -z "${CI_COMMIT_SHA}" ]; then
	exit 1
fi
if [ -z "${RUN_DATETIME}" ]; then
	RUN_DATETIME=$(date +"%Y%m%d-%H%M%S")
	echo "No run date time found (using fallback ${RUN_DATETIME})"
fi

SOURCE_FOLDER="$(pwd)/${TEST_DIRECTORY#./}"

# Original folder with just commit hash
DEST_FOLDER_ORIGINAL="/host/data/test/${CI_COMMIT_SHA}/"
mkdir -p "${DEST_FOLDER_ORIGINAL}"
touch "/host/data/test/${CI_COMMIT_SHA}/.keep"
cp -r "${SOURCE_FOLDER}" "${DEST_FOLDER_ORIGINAL}"
echo "Test data -> https://ci.2nd.dev/testdata/${CI_COMMIT_SHA}/"

# New folder with commit hash and datetime
FOLDER_NAME="${CI_COMMIT_SHA}_${DATETIME}"
DEST_FOLDER_TIMESTAMPED="/host/data/test/${FOLDER_NAME}/"
mkdir -p "${DEST_FOLDER_TIMESTAMPED}"
cp -r "${SOURCE_FOLDER}" "${DEST_FOLDER_TIMESTAMPED}"
echo "Test data (timestamped) -> https://ci.2nd.dev/testdata/${FOLDER_NAME}/"
