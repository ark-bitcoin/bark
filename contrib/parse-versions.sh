#!/usr/bin/env sh
set -e

UNPARSED_VERSION=$1
if [ -z "$UNPARSED_VERSION" ]; then
	exit 1
fi

case "$UNPARSED_VERSION" in
	aspd-*)
		echo "${UNPARSED_VERSION#aspd-}"
		;;
	bark-*)
		echo "${UNPARSED_VERSION#bark-}"
		;;
esac

