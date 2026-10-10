# Security policy

English | [Русский](SECURITY-RU.md)

Use DurkaHelper only for authorized defensive review and competition infrastructure. Treat source trees, configuration and reports as untrusted/sensitive input. The core does not execute scanned source, auto-apply patches or run exploitation probes.

## Reporting a security issue

Do **not** post credentials, private endpoints, live captures or an unredacted exploit against a real service in a public issue.

A verified private reporting channel is a **publication gate**. Before making the repository public, the maintainer must enable and test GitHub private vulnerability reporting or document another approved private channel here. This repository does not assert that private reporting is currently enabled, and it provides no unverified email address.

If GitHub's Security page offers **Report a vulnerability**, verify that it opens the private reporting flow before submitting. If it does not, request a private contact using a content-free public issue; do not include sensitive details until the channel is confirmed.

Include the affected commit, platform, minimal synthetic reproduction, expected/observed behavior and impact. Remove secrets from filenames, output and attachments.

## Supported security boundary

Only the current maintained revision is supported; there is no promise of backports to old toolchain pins. External integrations keep their own upstream policies and licenses. A pin improves reproducibility, not ongoing vulnerability remediation.

Report especially: source execution, secret disclosure, path traversal, symlink/race bypass, unsafe restore/overwrite, scope-comparison bypass, unintended Docker resources and publication-check false negatives. A clean static scan or secret scan is not a proof of safety.
