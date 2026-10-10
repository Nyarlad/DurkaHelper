---
name: Scanner false positive or false negative
about: Improve a detector using a small synthetic example
title: "[Scanner] RULE-ID: "
labels: ""
assignees: ""
---

English | [Русский](false_positive-RU.md)

## Rule and environment

- Rule ID and scanner commit/version:
- Language/runtime version:
- Detection engine, if known:
- Context schema and relevant non-secret priority setting, if any:

## Minimal synthetic example

Include code that may be published. Remove real credentials, identifiers,
private addresses and source owned by others. Do not attach a full scan report
or real repository when a small example will do.

## Expected result and reasoning

Explain whether the example should match and why. Include a contrasting safe or
unsafe case and the relevant documented detector limitation. For aliasing or
shadowing issues, include the surrounding binding statements.

## Reproduction and proposed coverage

Give the sanitized command and observed rule IDs/exit code. Suggest independent
positive and negative tests; do not rely only on changing a regex. Security
issues in the toolkit itself follow [SECURITY.md](../../SECURITY.md).
