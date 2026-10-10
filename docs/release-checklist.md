# Release and publication checklist

English | [Русский](release-checklist-RU.md)

Maintainer checklist, not an operator form. For deployment use the [Mac guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md). Publication readiness and competition readiness are separate.

## Source and tests

- [ ] Approved source commit and clean tracked tree; no unrelated changes.
- [ ] Full unit suite and coverage ledger pass, including English prose, paired Russian translations, identical code examples and links/anchors in both languages.
- [ ] New/changed rules meet independent positive/negative language coverage.
- [ ] Exact extracted core bundle passes; archive manifest/checksums verified.
- [ ] External kits pass the strict verifier; partial image exports are not advertised as a complete toolchain. A core-only release does not claim to contain third-party runtimes.
- [ ] Linux integration results and macOS ARM64 CI refer to explicit commits.
- [ ] Support claims match the current capability page; generated run outputs remain outside Git.

## Publication safety

Run from the repository root. These read-only checks report categories and locations, not matched secret values.

```bash
python3 scripts/publication_check.py --root . --allowlist config/publication-allowlist.json
python3 scripts/publication_check.py --root . --history --ref HEAD \
  --allowlist config/publication-allowlist.json
```

- [ ] Inspect every ref intended for publication, not only HEAD; the checker accepts repeated explicit --ref arguments.
- [ ] Use an ignored private denylist for local endpoint/identity strings when appropriate; never commit it.
- [ ] Review candidate archives, screenshots, CI artifacts and PR material separately. Text/history checking is not screenshot OCR or a proof that remote artifacts are safe.
- [ ] No keys/tokens, populated profiles, raw logs/PCAP, game data, personal paths or operator-specific deployment narrative.
- [ ] Synthetic exceptions are exact, narrow and justified; never broadly exempt tests/docs.
- [ ] Preserve legitimate authorship, citations and license attribution.
- [ ] Confirm a working private vulnerability-reporting channel as required by [SECURITY](../SECURITY.md).
- [ ] Third-party binary/image redistribution is reviewed; otherwise distribute core only.
- [ ] Version/changelog/support claims match the exact release.

Changing repository visibility, deleting refs, rewriting history or publishing third-party artifacts are separate deliberate actions. Do not automate them as a cosmetic cleanup.

## Release candidate and public access

`RELEASE_CANDIDATE_READY` means a fixed source commit and its core archive passed the applicable release checks, with remaining platform/event gates disclosed. It does not mean the repository is public or the competition environment is certified.

`PUBLIC_RELEASE_VERIFIED` additionally requires the owner's explicit publication approval and successful anonymous access to the intended repository, README, operator workflows and source download. Review all exposed branches/history, PR material and CI assets before that approval; retain legitimate history and test fixtures. Never silently delete historical material or rewrite commits to make a check green.

Public availability is a pre-event gate wherever required by the competition rules. A private release candidate does not satisfy that requirement. The [administrator workflows](ADMIN_WORKFLOWS.md) are the operational route; local validation outputs remain private.

## Competition gate

- [ ] Actual target-Mac architecture, exact OS/Desktop version and resource budget verified.
- [ ] Farm/coordinator/worker/Packmate functional paths and native recovery rehearsed.
- [ ] No unresolved P0 failure, partial result or unaccepted blocker.
- [ ] Full offline cold start succeeds without hidden downloads.
- [ ] Every physical teammate device passes authenticated useful scenarios and reconnect.
- [ ] Approved continuous capture sees known bidirectional traffic with bounded storage.
- [ ] At least 60 minutes of combined toolchain load; no secret-bearing capture source.
- [ ] A new operator can follow the English or Russian guide without AI; both routes remain complete.
