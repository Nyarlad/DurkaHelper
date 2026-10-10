
English | [Русский](PULL_REQUEST_TEMPLATE-RU.md)

## Outcome and scope

Describe the user-visible result, preserved compatibility and explicit limits.
Link issues without copying private operator data.

## Verification

- [ ] Targeted tests and the full local suite were run; exact results/skips are listed.
- [ ] CLI `0/1/2` behavior, read-only defaults and scope comparability are preserved.
- [ ] New/changed rules have independent positive/negative cases and honest limits.
- [ ] Catalog counts, stable anchors, local links, English prose and paired Russian translation checks pass; commands/examples stay identical.
- [ ] No target execution, hidden network access or expanded secrets were added.
- [ ] Mutations require approval, validate ownership and have scoped rollback.
- [ ] Offline packaging and publication checks cover the changed material.
- [ ] Third-party source/image pins, provenance and licenses remain explicit.

## Platform and evidence boundaries

List exact commits, platforms and tests performed. Mark unexecuted Mac,
Docker Desktop, physical-client, continuous-capture and offline-start scenarios
NOT_RUN or BLOCKED. Do not promote synthetic/Linux evidence into those claims.

## Release and safety

Document migration/rollback needs, unresolved release gates and operator actions.
Confirm that diff, history selected for publication, screenshots, artifacts and
discussion contain no private endpoints, credentials, raw logs or PCAP. A
vulnerability report follows [SECURITY.md](../SECURITY.md), not a public exploit
demonstration.
