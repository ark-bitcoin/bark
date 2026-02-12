# CHANGELOG Skill

When asked to create a CHANGELOG entry, follow these instructions strictly.

## First: Ask for the PR Number

Before writing any changelog entry, you MUST ask the user for the PR/MR number.

## File Location

Place changelog files in `CHANGELOG/unreleased/<crate>/<MR-number>`:
- `CHANGELOG/unreleased/bark/1485`
- `CHANGELOG/unreleased/server/1440`
- `CHANGELOG/unreleased/ark-lib/1472`

For changes spanning multiple crates, create a separate file in each affected crate's directory.

## Content Structure

### 1. Lead with the Value

Start with a clear explanation of what the feature is and why it's awesome.
The first line should be a short description, followed by context that explains
the benefit to users.

### 2. Highlight BREAKING Changes

If there are any BREAKING API changes, these MUST be highlighted in sub-bullets.
Use clear language like "**BREAKING:**" to call attention to these changes.

Example:
```
- Add environment variable support to Config
  Users can now configure bark using environment variables, making deployment
  in containerized environments much simpler.
  [#1234](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1234)
  - **BREAKING:** `Config::new()` now returns `Result<Config, ConfigError>`
  - **BREAKING:** Renamed `Config::load` to `Config::from_file`
```

## Format Rules

- Use `-` for bullet points (not `*`)
- First line: short description of the change (start with capital letter)
- Subsequent lines: indented with two spaces
- Link to the MR on the last line of the main entry (before sub-bullets)
- Use backticks for code references: `function_name`, `StructName`
- Keep descriptions concise but informative

## Template

```
- Short description of the change
  What problem it solves or how it benefits users.
  [#XXXX](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/XXXX)
  - **BREAKING:** Description of breaking change (if any)
```
