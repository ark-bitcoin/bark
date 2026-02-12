# Missing Changelogs Skill

When asked to find or add missing changelog entries, follow these instructions strictly.

## Step 1: Find the Last Release Tag

```bash
git describe --tags --abbrev=0
```

## Step 2: List All MR Numbers Since Last Release

```bash
git log <last-tag>..HEAD --oneline | grep -oE '![0-9]+' | sort -u
```

(MR numbers appear as `!1234` in merge commit messages)

## Step 3: Check Which MRs Have Changelog Entries

- List existing entries: `ls CHANGELOG/unreleased/*/`
- Compare against the MR numbers from git log

## Step 4: For Each Missing MR (One at a Time)

1. Run `git show --stat <merge-commit>` to see files changed
2. Determine which crate(s) were affected
3. Draft a changelog entry following the [changelog skill](./changelog.md)
4. Present to user:
   ```
   MR !1559 - "Commit message here"
   Affected crates: bark, server

   Proposed changelog for `bark`:
   - Short description of change
     [#1559](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1559)
   ```
5. **Ask user for approval before creating this entry**
6. If approved, write to `CHANGELOG/unreleased/<crate>/<MR-number>`
7. Proceed to next missing MR
