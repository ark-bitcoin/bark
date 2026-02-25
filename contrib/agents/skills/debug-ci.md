# Debugging CI Failures

## Step 1: Download CI Artifacts

```bash
bash ./contrib/agents/download-ci-artifacts.sh <ci-url>
```

Any CI URL works — the script downloads all failed steps in the pipeline.

Artifacts save to `./contrib/agents/ci-debugging/<pipeline>-<step_name>/`:
- `raw.log` — full decoded build log
- `testdata/<commit>/btc30/bark/<test_name>/` — per-test artifacts
  (server logs, bark logs, configs, databases)

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

Look at which CI steps failed:

- **Both `integration-mempool` and `integration-btc30.2` fail on the same
  test** → likely a real code bug. Go to [Step 4a](#step-4a-code-bug).
- **Only one backend fails, or only one test fails intermittently** → likely
  a flake (race condition). Go to [Step 4b](#step-4b-flake).

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

**Get a good run:**

```bash
KEEP_ALL_TEST_DATA=1 just int <test_name>
```

Local artifacts end up in `test/btc30/bark/<test_name>/`.

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
