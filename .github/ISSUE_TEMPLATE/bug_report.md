---
name: Bug report
about: Report a reproducible toolkit problem without private data
title: "[Bug] "
labels: ""
assignees: ""
---

English | [Русский](bug_report-RU.md)

## Safety check

Do not post credentials, private addresses, operator profiles, real flags,
traffic, raw logs or confidential source. For a security issue, read
[SECURITY.md](../../SECURITY.md) before submitting a public report.

## Expected and actual behavior

Describe the command's intended result and what happened instead. A static
finding is a review signal, not proof that a service is exploitable.

## Reproduction

Provide the smallest synthetic example, exact sanitized command, exit code and
bounded sanitized error. State whether this was a preview or an explicitly
applied action. Do not run destructive tests just to reproduce an issue.

## Environment

- DurkaHelper commit/version:
- OS and architecture:
- Python and ripgrep versions:
- For deployment only: Docker/Compose versions and image architecture:
- Last known working commit, if known:

## Scope and recovery

What was affected? Did the documented scoped rollback work? State whether the
problem concerns native core, a synthetic fixture or the maintained deployment.
