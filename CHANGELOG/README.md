# Changelog

We keep our users informed on changes we make to the software.
If you add a PR and end-users should know about it. Please
add an item to the CHANGELOG/unreleased.

To avoid conflicts we give each changelog item a name
that corresponds to the PR.

## Style Guide

> **Note:** We encourage humans to write changelog entries. This style guide
> should be interpreted leniently for human-written entries - don't let perfect
> formatting get in the way of documenting your changes. For AI-generated
> changelogs, these rules should be followed strictly.

### File Location

Place changelog files in `CHANGELOG/unreleased/<crate>/<MR-number>`:
- `CHANGELOG/unreleased/bark/1485`
- `CHANGELOG/unreleased/server/1440`
- `CHANGELOG/unreleased/ark-lib/1472`

For changes spanning multiple crates, create a separate file in each affected crate's directory.

### Format

```
- Short description of the change
  Additional context explaining what problem it solves or how it benefits users.
  [#1234](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1234)
  - Optional sub-bullet for specific details
  - Another sub-bullet if needed
```

### Rules

- Use `-` for bullet points (not `*`)
- First line: short description of the change (start with capital letter)
- Subsequent lines: indented with two spaces
- Link to the MR on the last line of the entry
- Use backticks for code references: \`function_name\`, \`StructName\`
- Keep descriptions concise but informative

### Example

```
- All `BarkPersister` trait methods are now async
  This enables non-blocking database operations throughout the wallet.
  [PR #1485](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1485)
```

See `CHANGELOG/unreleased/template.md` for a minimal template. 
