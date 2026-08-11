# Debugging CI Failures

## Step 1: Download CI Artifacts

The download script has two modes. Both accept either a bare id or the GitLab
URL you were given:

**Pipeline mode** — downloads logs and artifacts for all failed jobs in a
pipeline:

```bash
python3 ./contrib/agents/download-ci-artifacts.py --pipeline <id-or-url>
```

**Job mode** — downloads logs and artifacts for a single job (regardless of
its status):

```bash
python3 ./contrib/agents/download-ci-artifacts.py --job <job-id-or-url>
```

The script only needs `python3` and `wget`. It reads the public GitLab API
anonymously — no `glab`, no login. For a private project set `GITLAB_TOKEN`
in the environment first.

Artifacts save to `./contrib/agents/ci-debugging/<pipeline_id>-<job_name>/`:
- `raw.log` — full build log, with GitLab's per-line timestamps and terminal
  colour codes stripped
- `<test-dir>/<binary>/<test_name>/` — per-test artifacts (server logs, bark
  logs, configs, databases). `<test-dir>` is the job's test directory
  (`btc30`, `mempool`, `filestore`, `esplora`) and `<binary>` the test binary
  (`bark`, `barkd`, `exit`, `movement`, ...), matching the nextest failure
  line `ark-testing::<binary> <module>::<test_name>`.

## Step 2: Check Out the CI Commit

The CI may have run a different commit than your current HEAD. Extract the
commit hash from the testdata path in the download output and check it out:

```bash
git checkout <commit>
```

If the commit isn't available locally, fetch it first:

```bash
git fetch origin <commit>
```

This ensures you're reading the same code that CI ran against.

## Step 3: Identify the Failure

Check the end of each `raw.log` for the failure summary and test name.

## Step 4: Classify — Code Bug or Flake?

The same integration suite runs in several jobs, each on a different chain
source or datastore (see `.gitlab/tests.yml`):

| Job | Chain source | Runs |
|-----|--------------|------|
| `bark-btc30` | bitcoin core | always — the baseline |
| `bark-mempool` | mempool | always, but `allow_failure: true` |
| `bark-esplora` | esplora | merge trains only |
| `bark-filestore` | mempool, filestore | on `bark/src/persist` changes |

Look at which of them failed:

- **Several of these jobs fail on the same test** → likely a real code bug.
  Go to [Step 4a](#step-4a-code-bug).
- **Only one job fails, or only one test fails intermittently** → likely a
  flake (race condition). Go to [Step 4b](#step-4b-flake).

`core-server`, `bark-sdk` and `bark-int-action-reentrancy` run other suites,
so a failure there points at that suite rather than at the chain source.

### Step 4a: Code Bug

The failure is deterministic. Analyze the git log for context:

```bash
git log --oneline -20
```

Read the recent commits and understand what changed. The bug is most likely
in code touched by recent commits. Read the failing test and the changed code,
identify the mismatch, and propose a fix.

### Step 4b: Flake

The failure is a race condition — probably pre-existing. You need to compare
a bad CI run against a good local run to find where state diverges.

**Get a good run**, using the chain source of the job that failed:

```bash
KEEP_ALL_TEST_DATA=1 just int <test_name>          # bitcoin core (bark-btc30)
KEEP_ALL_TEST_DATA=1 just int-mempool <test_name>  # mempool (bark-mempool)
KEEP_ALL_TEST_DATA=1 just int-esplora <test_name>  # esplora (bark-esplora)
```

For `bark-filestore`, prefix the mempool run with `USE_FILESTORE=1`.

Local artifacts end up in `test/<binary>/<test_name>/` — the same layout as
in CI, minus the `<test-dir>` level that CI sets via `TEST_DIRECTORY`.

**Compare CI vs local logs.** Focus on:
- Timing differences (round start/end, block generation)
- Round lifecycle divergence (extra rounds firing, rounds completing early)
- The exact point where the two runs diverge

**Your output must include a sequence of events** that explains the race
condition causing the flake. For example:

> 1. Test boards a VTXO and calls `refresh_all`
> 2. `refresh_all` waits for the next round
> 3. An automatic round fires *before* the explicit round the test expects
> 4. The VTXO gets refreshed in the unexpected round, creating an extra movement
> 5. The assertion on `movements.len()` fails (expected 3, got 4)

This timeline is the key deliverable — it tells the developer exactly what
race to eliminate.

## Step 5: Cleanup

```bash
rm -rf ./contrib/agents/ci-debugging/
```

The `ci-debugging/` directory is gitignored.
