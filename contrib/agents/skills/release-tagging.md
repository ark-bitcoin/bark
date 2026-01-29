# Release Tagging Skill

When asked to tag a release, follow these steps.

## Step 0: Check for Missing Changelog Entries

Ask the user if they want to check for missing changelog entries before proceeding.

If yes, follow the [missing-changelogs skill](./missing-changelogs.md) to identify and add any missing entries, then proceed to Step 1.

## Step 1: Show Current Versions

List all crates and their current versions from `Cargo.toml` files:

```
Crate            Current Version
─────────────────────────────────
ark-lib          x.y.z
bark             x.y.z
bark-json        x.y.z
...
```

## Step 2: Propose New Versions

Based on the changes in `CHANGELOG/unreleased/`, propose new versions:

- **BREAKING changes** → bump major (or minor if < 1.0)
- **New features** → bump minor
- **Bug fixes only** → bump patch

Present the proposal:

```
Crate            Current    Proposed
────────────────────────────────────
ark-lib          x.y.z   →  x.y.z
bark             x.y.z   →  x.y.z
...
```

## Step 3: Show the Plan

Before making changes, list ALL files that will be modified:

```
Files to update:
- crates/ark-lib/Cargo.toml (version)
- crates/bark/Cargo.toml (version + dependency versions)
- CHANGELOG.md (merge all unreleased entries)
...
```

**Wait for user approval before proceeding.**

## Step 4: Update Versions

Update version numbers in:
- Each crate's `Cargo.toml`
- Cross-crate dependency versions in `Cargo.toml` files

## Step 5: Merge Changelogs

All changelog entries go into a single `CHANGELOG.md` file:

1. Read all files from `CHANGELOG/unreleased/<crate>/` for each crate
2. Add a new version section to `CHANGELOG.md` (after the header, before previous versions):
   ```markdown
   # vX.Y.Z

   - `crate-name`
     - Entry from MR 1234
     - Entry from MR 1235
   - `another-crate`
     - Entry from MR 1236
   ```
3. Delete the merged files from `CHANGELOG/unreleased/<crate>/`

## Step 6: Verify Build

Run:
```
just checks
```

## Step 7: Summary

Show what was done:
- Versions updated
- Changelog entries merged into `CHANGELOG.md`
- Files deleted from unreleased

Remind user to:
1. Review the changes
2. Commit with message: `Release vX.Y.Z`
3. Create git tag: `git tag vX.Y.Z`
4. Push: `git push --follow-tags`
