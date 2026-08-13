# CHANGELOG Skill

- Follow these instructions when you write a CHANGELOG entry.
- Follow `CONTRIBUTING/style_guide.md` for vocabulary and writing style.

## Before You Write

- Ask the user for the PR/MR number before you write a changelog entry.

## File Location

- Put changelog files in `CHANGELOG/unreleased/<crate>/<MR-number>`.
- Examples:
  - `CHANGELOG/unreleased/bark/1485`
  - `CHANGELOG/unreleased/server/1440`
  - `CHANGELOG/unreleased/ark-lib/1472`
- If a change affects more than one crate, make one file for each crate.

## Content

- Start with a short description of the feature.
- Explain why the change helps users.
- If the change breaks the API, mark it with `**BREAKING:**`.

Example:

```
- Add environment variable support to Config
  Users can now configure bark with environment variables. This makes
  deployment in containerized environments much simpler.
  [#1234](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1234)
  - **BREAKING:** `Config::new()` now returns `Result<Config, ConfigError>`
  - **BREAKING:** Renamed `Config::load` to `Config::from_file`
```

## Format

- Use `-` for bullet points. Do not use `*`.
- Start the first line with a capital letter.
- Indent the lines after the first line with two spaces.
- Put the MR link on the last line of the main entry.
- Put sub-bullets after the MR link.
- Use backticks for code: `function_name`, `StructName`.
- Keep text short and informative.

## Template

```
- Short description of the change
  What problem it solves or how it benefits users.
  [#XXXX](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/XXXX)
  - **BREAKING:** Description of breaking change (if any)
```
