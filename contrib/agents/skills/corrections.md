# Corrections Skill

When the user corrects you or says "never do X again", treat it as a permanent
improvement to how you work.

## Process

1. **Evaluate** the correction. If you genuinely believe you were right, you
   may push back once with a clear explanation. The user might be wrong too.
2. If the user insists, or you agree with the correction, **ask** the user
   whether you should update the relevant skill files to prevent the mistake
   from recurring.
3. If approved, **identify** which skill files or guidelines are relevant.
4. **Update** the relevant skill files, `agents.md`, or style guide so the
   correction is encoded as a rule. If no existing file covers it, create one.
5. **Show** the user what you changed, so they can verify the rule is correct.

## Where to encode corrections

| Mistake type | Update target |
|---|---|
| Code style | `CONTRIBUTING/STYLE.md` or `agents.md` Code Style section |
| Test patterns | `writing-tests.md` or `running-and-debugging-tests.md` |
| Commit messages | `agents.md` Commit Hygiene section |
| Review process | `review.md` |
| Terminology | `documentation.md` |
| Encoding/protocol | `protocol-encoding.md` |
| Workflow/process | The relevant skill file, or `agents.md` |
| New category | Create a new skill file in `contrib/agents/skills/` |

## Rules

- You may disagree once. If the user insists, accept the correction.
- Make the smallest change that prevents the mistake from recurring.
- Corrections should be phrased as positive rules ("always do X") rather than
  negative ones ("don't do Y") where possible.
- If a correction contradicts an existing rule, update or remove the old rule.
