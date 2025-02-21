# Extra information

## check-clean-default-config.sh
This script checks if file `aspd/config.default.toml` is dirty.
When it is dirty it will print the diff + exit code 1.

## check-commits.sh
This script automates the process of cherry-picking commits from a feature branch onto the master branch while running predefined checks. It is designed to work in both local and CI environments.

#### Features

- **Identifies the base branch** (`master`) and the feature branch (from CI variables or local development).
- **Determines the base commit** where the feature branch diverged from `master`.
- **Lists all commits** from the feature branch since the divergence point.
- **Cherry-picks each commit** onto `master`, running validation checks (`just prechecks` and `just check`).
- **Handles cherry-pick failures** gracefully by aborting and running an alternative workflow.

#### Workflow

1. **Detects master branch:**
    - Tries to find `origin/master` or falls back to a local `master` branch.
    - Exits with an error if no master branch is found.

2. **Determines the feature branch:**
    - Uses `CI_COMMIT_SOURCE_BRANCH` or `CI_COMMIT_SHA` in a CI environment.
    - Defaults to the current commit hash in a local development context.

3. **Finds the base commit:**
    - Uses `git merge-base` to locate the common ancestor of `master` and the feature branch.

4. **Processes commits one by one:**
    - Iterates over commits and attempts to cherry-pick them onto `master`.
    - Runs validation checks (`just check`) after each commit.
    - If a cherry-pick fails, it aborts and marks a failure.

5. **Fallback on failure:**
    - If cherry-picking fails, it switches to an alternative approach:
    - Checks out each commit individually and runs the validation checks.

## check-versions.sh
1. tag-name

This is a helper script for CI so it can verify the version number from the tag.
It compares this version number with the version number defined in Cargo.toml of the respective project.
There are 3 tagging options:
* `aspd-0.0.1` this will check if `0.0.1` is also specified as version in `aspd/Cargo.toml`
* `bark-0.0.1` this will check if `0.0.1` is also specified as version in `bark/Cargo.toml`
* `all-0.0.1` this will check if `0.0.1` is also specified as version in both `aspd/Cargo.toml` and `bark/Cargo.toml`

## generate-index.sh
#### parameters:
1. parent-dir

#### info:
This will generate an `index.html` at the provided <parent-dir>
that automatically forwards to `bark/struct.Wallet.html`

## parse-versions.sh
#### parameters:
1. tag-name

This is a helper script for CI so it can parse the version number from the tag.
There are 3 tagging options:
* `aspd-0.0.1`
* `bark-0.0.1`
* `all-0.0.1`

This script will return `0.0.1` for all 3 cases.

## prechecks.sh
#### Parameters:
1. "rust_no_spaces_for_indent" or "unused_aspd_logs"

#### rust_no_spaces_for_indent:
We don't allow any line that starts with a whitespace.
Exit code 2 if whitespace is found.
#### unused_aspd_logs:
Check if there are structure log messages in aspd-logs that are not used.
