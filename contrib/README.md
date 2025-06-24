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
There are 2 tagging options:
* `aspd-0.0.1` this will check if `0.0.1` is also specified as version in `aspd/Cargo.toml`
* `bark-0.0.1` this will check if `0.0.1` is also specified as version in `bark/Cargo.toml`

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
There are 2 tagging options:
* `aspd-0.0.1`
* `bark-0.0.1`

This script will return `0.0.1` for all cases.

## prechecks.sh
#### Parameters:
1. "rust_no_spaces_for_indent", "rust_no_whitespace_on_empty_lines" or "unused_aspd_logs"

#### rust_no_spaces_for_indent:
We don't allow any line that starts with a whitespace.
Exit code 2 if whitespace is found.
#### rust_no_whitespace_on_empty_lines:
We don't allow empty lines to contain whitespace.
Exit code 2 if an empty line with whitespace is found.
#### unused_aspd_logs:
Check if there are structure log messages in aspd-logs that are not used.

## ci-run-test.sh
#### Parameters:
1. `<TEST>` — e.g. `test-integration` or `test-integration-codecov`

#### Description:
Runs a `just` task for the given test with a watchdog and automatic data copy.
- Executes `just <TEST>`.
- Triggers `./contrib/ci-run-test-copy.sh` as a data copy step in all exit scenarios:
   - Normal completion
   - Manual interruption (e.g. Ctrl+C)
   - CI-enforced timeout

#### Watchdog Behavior:
- A background watchdog sleeps for 55 minutes (3300 seconds).
- If the task is still running after that time, the watchdog:
   - Prints a warning
   - Calls the data copy script
   - Terminates the main process to avoid CI timeout (like Woodpecker's 1-hour limit)

#### Exit Codes:
- Returns the same exit code as `just <TEST>`.
- Data copy always runs before exit.

## ci-run-test-copy.sh
#### Environment Variables:
1. `TEST_DIRECTORY` — Relative path to the test folder (e.g. `./test/btc29`)
2. `CI_COMMIT_SHA` — Git commit SHA used to create a unique destination path

#### Description:
Copies test data from the current repository into a persistent location tied to the current commit SHA.

- Converts the relative `TEST_DIRECTORY` to an absolute path using `pwd`
- Copies the entire directory to:  
  `/host/data/test/<CI_COMMIT_SHA>/`
- Ensures the destination directory exists before copying

#### Output:
Prints a link to where the test data can be accessed:
```
Test data -> https://ci.2nd.dev/testdata/<CI_COMMIT_SHA>/
```

#### Exit Codes:
- Exits with `1` if either `TEST_DIRECTORY` or `CI_COMMIT_SHA` is not set
- Exits with `0` on success
