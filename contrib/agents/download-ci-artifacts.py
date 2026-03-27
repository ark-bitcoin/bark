#!/usr/bin/env python3
"""
Download CI logs and test artifacts from GitLab CI.

Requires: glab (GitLab CLI) authenticated, wget (for testdata downloads).

Usage:
    python3 ./contrib/agents/download-ci-artifacts.py --pipeline <id>
    python3 ./contrib/agents/download-ci-artifacts.py --job <id>

Examples:
    # Download all failed jobs in a pipeline:
    python3 ./contrib/agents/download-ci-artifacts.py --pipeline 2411091890

    # Download a specific job (even if it passed):
    python3 ./contrib/agents/download-ci-artifacts.py --job 13666140734
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote as urlquote


SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_BASE = SCRIPT_DIR / "ci-debugging"
REPO = "ark-bitcoin/bark"


def glab_api(endpoint, repo=None, paginate=False):
    """Call glab api and return parsed JSON (or raw text for traces)."""
    cmd = ["glab", "api", endpoint]
    if repo:
        cmd += ["-R", repo]
    if paginate:
        cmd += ["--paginate"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: glab api failed for {endpoint}")
        print(result.stderr.strip())
        sys.exit(1)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout


def get_failed_jobs(repo, pipeline_id):
    """Return list of failed jobs in a pipeline."""
    encoded = urlquote(repo, safe="")
    return glab_api(
        f"/projects/{encoded}/pipelines/{pipeline_id}/jobs?scope[]=failed&per_page=100",
        paginate=True,
    )


def get_job(repo, job_id):
    """Return a single job object."""
    encoded = urlquote(repo, safe="")
    return glab_api(f"/projects/{encoded}/jobs/{job_id}")


def get_job_trace(repo, job_id):
    """Return the plain-text log of a job."""
    encoded = urlquote(repo, safe="")
    return glab_api(f"/projects/{encoded}/jobs/{job_id}/trace")


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
    for line in trace.splitlines():
        if re.match(r"^---- .* stdout ----$", line) or re.match(r"^    [a-z_]+$", line):
            print(f"  {line.strip()}")


def main():
    parser = argparse.ArgumentParser(
        description="Download CI logs and test artifacts from GitLab CI.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--pipeline",
        metavar="ID",
        type=int,
        help="Download all failed jobs in a pipeline.",
    )
    group.add_argument(
        "--job",
        metavar="ID",
        type=int,
        help="Download a specific job (regardless of status).",
    )
    args = parser.parse_args()

    if args.job:
        job = get_job(REPO, args.job)
        print(f"Project: {REPO}, Job: {args.job} ({job['name']}), Status: {job['status']}")
        process_job(REPO, job)
    else:
        print(f"Project: {REPO}, Pipeline: {args.pipeline}")
        jobs = get_failed_jobs(REPO, args.pipeline)
        if not jobs:
            print(f"No failed jobs found in pipeline {args.pipeline}.")
            sys.exit(0)

        print("Failed jobs to download:")
        for job in jobs:
            print(f"  {job['name']} (id={job['id']})")

        for job in jobs:
            process_job(REPO, job)

    print()
    print("===== All downloads complete =====")


if __name__ == "__main__":
    main()
