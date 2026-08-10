#!/usr/bin/env python3
"""
Download CI logs and test artifacts from GitLab CI.

Uses the public GitLab API only: no `glab` and no login are needed, since the
bark project and its CI logs are public. Set GITLAB_TOKEN in the environment
to reach a private project.

Requires: python3, wget (for testdata downloads).

Usage:
    python3 ./contrib/agents/download-ci-artifacts.py --pipeline <id-or-url>
    python3 ./contrib/agents/download-ci-artifacts.py --job <id-or-url>

Examples:
    # Download all failed jobs in a pipeline:
    python3 ./contrib/agents/download-ci-artifacts.py --pipeline 2747928504

    # Same, passing the pipeline URL straight from the MR page:
    python3 ./contrib/agents/download-ci-artifacts.py \
        --pipeline https://gitlab.com/ark-bitcoin/bark/-/pipelines/2747928504

    # Download a specific job (even if it passed):
    python3 ./contrib/agents/download-ci-artifacts.py --job 15815014046
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote as urlquote, urlencode


SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_BASE = SCRIPT_DIR / "ci-debugging"
GITLAB = "https://gitlab.com"
REPO = "ark-bitcoin/bark"
TOKEN = os.environ.get("GITLAB_TOKEN")

# GitLab prefixes every log line with "<timestamp> <NN><stream><flag>", where a
# "+" flag marks the continuation of a line that GitLab wrapped.
LOG_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z \d\d[OE]([ +])")
ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def http_get(url, what):
    """GET a URL, returning (body, headers). Exits on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "bark-ci-debug"})
    if TOKEN:
        req.add_header("PRIVATE-TOKEN", TOKEN)

    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.headers
    except urllib.error.HTTPError as e:
        print(f"ERROR: could not fetch {what}: HTTP {e.code} ({url})")
        if e.code in (401, 403, 404) and not TOKEN:
            print("If the project is private, set GITLAB_TOKEN and retry.")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: could not fetch {what}: {e.reason}")
        sys.exit(1)


def api_get(path, params=None):
    """Call the GitLab REST API. Lists are fetched across all pages."""
    query = dict(params or {}, per_page=100)
    items = []
    page = 1
    while True:
        url = f"{GITLAB}/api/v4{path}?{urlencode(dict(query, page=page))}"
        body, headers = http_get(url, f"API {path}")
        data = json.loads(body)
        if not isinstance(data, list):
            return data

        items += data
        next_page = headers.get("X-Next-Page")
        if not next_page:
            return items
        page = int(next_page)


def get_failed_jobs(repo, pipeline_id):
    """Return list of failed jobs in a pipeline."""
    encoded = urlquote(repo, safe="")
    return api_get(
        f"/projects/{encoded}/pipelines/{pipeline_id}/jobs",
        {"scope[]": "failed"},
    )


def get_job(repo, job_id):
    """Return a single job object.

    The REST endpoint for a single job requires authentication even on public
    projects, so anonymously we use the web UI's JSON endpoint instead and
    normalise it to the shape the jobs list returns.
    """
    if TOKEN:
        encoded = urlquote(repo, safe="")
        return api_get(f"/projects/{encoded}/jobs/{job_id}")

    body, _ = http_get(f"{GITLAB}/{repo}/-/jobs/{job_id}.json", f"job {job_id}")
    job = json.loads(body)
    return {
        "id": job["id"],
        "name": job["name"],
        "status": job.get("status", {}).get("label", "unknown"),
        "pipeline": {"id": job["pipeline"]["id"]},
    }


def get_job_trace(repo, job_id):
    """Return the plain-text log of a job."""
    encoded = urlquote(repo, safe="")
    # The API trace endpoint needs authentication, the web one doesn't.
    url = (
        f"{GITLAB}/api/v4/projects/{encoded}/jobs/{job_id}/trace" if TOKEN
        else f"{GITLAB}/{repo}/-/jobs/{job_id}/raw"
    )
    body, _ = http_get(url, f"log of job {job_id}")
    return clean_trace(body)


def clean_trace(trace):
    """Undo GitLab's per-line timestamping and strip terminal colour codes."""
    lines = []
    for line in trace.split("\n"):
        match = LOG_PREFIX.match(line)
        if not match:
            lines.append(line)
        elif match.group(1) == "+" and lines:
            # Continuation of a wrapped line: glue it back onto the previous.
            lines[-1] += line[match.end():]
        else:
            lines.append(line[match.end():])

    return ANSI.sub("", "\n".join(lines))


def parse_ref(value, kind):
    """Parse a pipeline/job reference: either a bare id or a GitLab URL.

    Returns (repo, id); a bare id is assumed to belong to the bark repo.
    """
    if value.isdigit():
        return REPO, int(value)

    match = re.match(rf"https?://[^/]+/(.+?)/-/{kind}s/(\d+)", value)
    if not match:
        sys.exit(f"ERROR: not a {kind} id or {kind} URL: {value}")
    return match.group(1), int(match.group(2))


def download_testdata(url, dest_dir):
    """Recursively download a testdata directory using wget."""
    print(f"  Downloading artifacts from {url} ...")
    try:
        subprocess.run(
            [
                "wget",
                "--recursive",
                "--no-parent",
                "--no-host-directories",
                "--cut-dirs=2",
                "--directory-prefix", str(dest_dir),
                "--reject", "index.html*,robots.txt",
                "--quiet",
                url,
            ],
            check=False,
        )
    except FileNotFoundError:
        print("  WARNING: wget not found, skipping testdata download")


def process_job(repo, job):
    """Download logs and artifacts for a single job."""
    job_id = job["id"]
    job_name = job["name"]
    pipeline_id = job["pipeline"]["id"]

    print()
    print(f"========== {job_name} (job {job_id}) ==========")

    outdir = OUTPUT_BASE / f"{pipeline_id}-{job_name}"
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {outdir}")

    print("Fetching logs...")
    trace = get_job_trace(repo, job_id)
    raw_log = outdir / "raw.log"
    raw_log.write_text(trace)
    line_count = trace.count("\n")
    print(f"Saved logs to {raw_log} ({line_count} lines)")

    # Extract testdata URLs
    testdata_urls = set(re.findall(r"https://ci\.2nd\.dev/testdata/\S+/", trace))

    if not testdata_urls:
        print("No testdata URLs found in logs.")
    else:
        print("Found testdata URLs:")
        for url in sorted(testdata_urls):
            print(f"  {url}")
        for url in sorted(testdata_urls):
            download_testdata(url, outdir)

    # Print failed tests summary
    print()
    print("Failed tests:")
    seen = set()
    for line in trace.splitlines():
        # cargo-nextest reports failures and its summary indented; the
        # `---- <test> stdout ----` form is what plain cargo test prints.
        summary = re.match(r"^\s+((?:TRY \d+ )?FAIL|Summary) \[", line)
        if summary or re.match(r"^---- .* stdout ----$", line):
            if line.strip() not in seen:
                seen.add(line.strip())
                print(f"  {line.strip()}")


def main():
    parser = argparse.ArgumentParser(
        description="Download CI logs and test artifacts from GitLab CI.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--pipeline",
        metavar="ID_OR_URL",
        help="Download all failed jobs in a pipeline.",
    )
    group.add_argument(
        "--job",
        metavar="ID_OR_URL",
        help="Download a specific job (regardless of status).",
    )
    args = parser.parse_args()

    if args.job:
        repo, job_id = parse_ref(args.job, "job")
        job = get_job(repo, job_id)
        print(f"Project: {repo}, Job: {job_id} ({job['name']}), Status: {job['status']}")
        process_job(repo, job)
    else:
        repo, pipeline_id = parse_ref(args.pipeline, "pipeline")
        print(f"Project: {repo}, Pipeline: {pipeline_id}")
        jobs = get_failed_jobs(repo, pipeline_id)
        if not jobs:
            print(f"No failed jobs found in pipeline {pipeline_id}.")
            sys.exit(0)

        print("Failed jobs to download:")
        for job in jobs:
            print(f"  {job['name']} (id={job['id']})")

        for job in jobs:
            process_job(repo, job)

    print()
    print("===== All downloads complete =====")


if __name__ == "__main__":
    main()
