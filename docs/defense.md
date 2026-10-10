# Defense operator workflow

English | [Русский](defense-RU.md)

[Quick sheet](defense-cheatsheet.md) · [Catalog](vulnerabilities/README.md) · [Patch verification](patch-validation.md)

## Before the first change

Confirm authorized scope and the [competition contract](competition-rules.md). Assign one deployment owner per service. Record the actual code/image revision, startup mechanism, configuration sources, required ports, data locations and rollback method.

Run a normal user operation and retain synthetic/authorized old records for regression checks. A healthy endpoint does not prove login, authorization, persistence or checker compatibility.

Create a scoped [baseline](local-tools.md#defense-operations), source scan and approved health profile. Preserve read-only source copies; never use broad process/container inventory to expose unrelated workloads.

## Repeated loop

1. Observe checker status, explicit health checks and application behavior.
2. Compare snapshots for file/configuration/process/listener drift.
3. Review the smallest relevant log/traffic interval locally.
4. Trace a suspicious operation to an invariant in source.
5. Add a failing regression test and make the smallest compatible patch.
6. Repeat owner/other-user/anonymous, legacy-data and availability checks.
7. Deploy through the rehearsed path; monitor and roll back the code/image if regression occurs.

Do not rotate keys, migrate schemas, replace runtimes or remove functionality as incidental changes. Old data created in later rounds must survive code rollback.

## Triage and evidence

A scanner finding or suspicious-looking request is a hypothesis, not proof of compromise. Compare with normal traffic, timestamps and actual state changes. Preserve only required evidence privately; record normalized events and sanitized hashes using [timeline/evidence tools](local-tools.md#patch-evidence-timelines-and-export).

Do not publish raw logs, PCAP, cookies, flags, request bodies, Neo info or expanded Compose configuration. Keep diagnostic terminals and secret-bearing interfaces private.

## Recovery

Verify the backup before relying on it. Restore into a new isolated staging environment and check data/functionality before any approved production action. Use database-native dumps or controlled consistent cold copies; copying a live database file is not a reliable backup.

Initial rehearsal objectives are RPO five minutes and RTO ten minutes, measured per component. Synthetic subsecond drills do not prove these objectives for real data volumes. Submission and workers remain stopped until restored/expired queues are reviewed.

When evidence is incomplete, report partial/blocked rather than safe. Use the [game-day runbook](game-day.md) for operational failures and the [admin sheet](TEAM_LAN_ADMIN_CHEATSHEET.md) for shared-tool access.
