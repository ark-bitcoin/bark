# Branch Review Skill

When asked to review a branch, follow these instructions. There are two modes:

- **Review & fix-up** (default): You may apply simple fixes
- **Read-only review**: Document findings only, make no changes

## Output Location

Write your review to `contrib/agents/reviews/<branch-name>.md`.

## Allowed Fix-ups (review & fix-up mode only)

You may ONLY perform simple fix-ups:

- Solve rebase conflicts
- Fix spelling mistakes
- Small cosmetic changes (whitespace, formatting)
- Fix-up commit messages

Do NOT attempt to fix hard architectural problems, complex refactoring, or
design issues. Document these in the review instead.

## Build Verification

Run `just check commits` to verify the branch.

## Review Checklist

For each commit, check:

1. **Typos and spelling** - variable names, comments, documentation, commit messages
2. **Inconsistencies** - naming conventions, code style, patterns used elsewhere
3. **Unused code** - unused variables, unnecessary imports, dead code
4. **Vulnerabilities** - injection flaws, unsafe deserialization, unchecked inputs, panics from untrusted data, resource exhaustion (DoS vectors)
5. **Skills adherence** - `protocol-encoding.md` if touching ProtocolEncoding, `changelog.md` if a changelog entry is needed

## Review Template

```markdown
# Review: <branch-name>

## High-Level Overview

[Assessment of overall PR quality: overengineered? duplication? best practices?]

## Security Review

[Vulnerability scan results]

## Commit-by-Commit Review

### Commit: <hash> <short message>
- **Summary:** [what it does]
- **Issues:** [any problems found]
- **Fix-ups applied:** [list of fixes, or "N/A" for read-only review]
```

## Workflow

1. Identify the branch to review
2. Create the review output directory
3. Get the commit list for the branch
4. For each commit:
   - Review the changes
   - Document findings
   - Apply allowed fix-ups if needed (fix-up mode only)
   - Run build verification after any changes
5. Write the complete review to the output file
