#!/usr/bin/env bash
#
# Download CI logs and test artifacts for all failed steps in a pipeline.
#
# Usage:
#   ./contrib/agents/download-ci-artifacts.sh <ci-url>
#
# Example:
#   ./contrib/agents/download-ci-artifacts.sh https://ci.2nd.dev/repos/6/pipeline/3387
#   ./contrib/agents/download-ci-artifacts.sh https://ci.2nd.dev/repos/6/pipeline/3397/4
#   ./contrib/agents/download-ci-artifacts.sh https://ci.2nd.dev/repos/6/pipeline/3401/21
#
# Any trailing path after the pipeline number is ignored. The script always
# downloads all failed steps across the entire pipeline.

set -euo pipefail

CI_BASE="https://ci.2nd.dev"

if [ $# -lt 1 ]; then
	echo "Usage: $0 <ci-url>"
	echo "Example: $0 https://ci.2nd.dev/repos/6/pipeline/3401"
	exit 1
fi

URL="$1"

# Parse URL — extract repo_id and pipeline_number, ignore anything after
if [[ "$URL" =~ repos/([0-9]+)/pipeline/([0-9]+) ]]; then
	REPO_ID="${BASH_REMATCH[1]}"
	PIPELINE="${BASH_REMATCH[2]}"
else
	echo "ERROR: Could not parse URL. Expected format:"
	echo "  https://ci.2nd.dev/repos/<repo_id>/pipeline/<pipeline_number>"
	exit 1
fi

echo "Repo: $REPO_ID, Pipeline: $PIPELINE"

# Fetch pipeline metadata
PIPELINE_JSON=$(curl -sf "${CI_BASE}/api/repos/${REPO_ID}/pipelines/${PIPELINE}")

# Collect all failed steps across the entire pipeline
STEPS=$(echo "$PIPELINE_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for wf in data.get('workflows', []):
    for step in wf.get('children', []):
        if step['state'] == 'failure':
            print(step['id'], step['name'])
")

if [ -z "$STEPS" ]; then
	echo "No failed steps found in pipeline $PIPELINE."
	exit 0
fi

echo "Failed steps to download:"
echo "$STEPS" | while read -r sid sname; do echo "  $sname (id=$sid)"; done

# Process each step
download_step() {
	local STEP_ID="$1"
	local STEP_NAME="$2"

	echo ""
	echo "========== $STEP_NAME (id=$STEP_ID) =========="

	# Create output directory
	OUTDIR="./contrib/agents/ci-debugging/${PIPELINE}-${STEP_NAME}"
	mkdir -p "$OUTDIR"
	echo "Output directory: $OUTDIR"

	# Fetch and decode logs
	echo "Fetching logs..."
	curl -sf "${CI_BASE}/api/repos/${REPO_ID}/logs/${PIPELINE}/${STEP_ID}" \
		| python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for entry in data:
    d = entry.get('data')
    if d is None:
        print()
        continue
    print(base64.b64decode(d).decode('utf-8', 'replace'))
" > "$OUTDIR/raw.log"

	echo "Saved logs to $OUTDIR/raw.log ($(wc -l < "$OUTDIR/raw.log") lines)"

	# Extract testdata URLs from the logs
	TESTDATA_URLS=$(grep -oP 'https://ci\.2nd\.dev/testdata/[^\s]+/' "$OUTDIR/raw.log" || true)

	if [ -z "$TESTDATA_URLS" ]; then
		echo "No testdata URLs found in logs."
		return
	fi

	echo "Found testdata URLs:"
	echo "$TESTDATA_URLS"

	# Download artifacts recursively using wget
	for TESTDATA_URL in $TESTDATA_URLS; do
		echo "Downloading artifacts from $TESTDATA_URL ..."
		wget \
			--recursive \
			--no-parent \
			--no-host-directories \
			--cut-dirs=1 \
			--directory-prefix="$OUTDIR" \
			--reject="index.html*,robots.txt" \
			--quiet \
			"$TESTDATA_URL" \
			|| echo "WARNING: wget had issues downloading from $TESTDATA_URL"
	done

	echo ""
	echo "Failed tests:"
	grep -E '^---- .* stdout ----$|^    [a-z_]+$' "$OUTDIR/raw.log" | tail -20 || true
}

echo "$STEPS" | while read -r sid sname; do
	download_step "$sid" "$sname"
done

echo ""
echo "===== All downloads complete ====="
