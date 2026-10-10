# Game-day runbook

English | [Русский](game-day-RU.md)

This is the short operating guide after a successful [deployment rehearsal](MACOS_FULL_DEPLOYMENT_AND_TESTING.md). Follow organizer scope and keep one deployment owner per service.

## Receive a service

Identify its real source/startup/configuration/data paths and immutable revision. Keep game-service projects separate from the team's S4DFarm/Neo/Packmate projects.

Evidence: `REVIEWED`; effect `READ-ONLY`; cwd the authorized service's actual Compose directory. Prerequisite: correct daemon/project and approved access. Expected: only that project's service list/state; local output may reveal paths. Rollback: none.

```bash
pwd
docker compose config --services
docker compose ps -a
```

If deployment uses explicit project/file options, use those exact same options. Do not print expanded configuration. Execute one normal user scenario and save an authorized old-data sample. Then establish the scoped baseline and source scan.

## Availability failure

Preserve the failure timestamp and last change. Inspect only the affected project's state, dependency health and bounded private logs; logs can contain secrets and must stay out of public evidence exports. Avoid unscoped host-wide container/process listings on shared systems.

| Symptom | Next check |
|---|---|
| Stopped/restarting component | Exit reason, startup settings, dependency readiness |
| UI works but actions fail | Database, persistence, exact API/authentication |
| Host works but teammate cannot connect | Ethernet address, published port, host policy, client path |
| Failure started after patch | Exact diff and rehearsed code/image rollback |
| Health passes but checker fails | Real checker semantics, normal scenario and old data |
| Queue is not moving | Approved protocol, limits, receiver response and submission state |
| Neo cannot connect | Correct client version, coordinator address/key and farm reachability |
| Packmate has no streams | Source visibility, mode, service registration and time window |

Restarting does not repair lost data. Do not use down -v, delete volumes or mutate networking on suspicion. Understand persistence before restarting.

## Suspicious traffic

Use an approved observation point and a short timestamp range. Compare request/response, method/path, parameter types, size/status and application events with normal behavior. Retain only the needed private evidence.

Same LAN does not imply packet visibility. A Packmate UI with no known request/response is not a working capture setup. FILE import is a fallback, not proof of continuous LIVE analysis.

## Patch loop

[Review code](code-review.md) → [catalog recipe](vulnerabilities/README.md) → [regression/deployment/rollback](patch-validation.md). Preserve normal behavior and current data; do not remove a required feature merely to silence a signal.

For explicit health checks, privately adapt [services.example.json](../config/services.example.json); never put passwords in URLs. Evidence: `REVIEWED`; effect `READ-ONLY` GETs; cwd root; expected all configured checks true.

```bash
python3 scripts/http_probe.py local/services.json --timeout 2 --workers 2
```

This checks configured HTTP behavior, not Neo gRPC, full login or game checker semantics. [Local tools](local-tools.md) document formats and limits. Shared infrastructure failures use the [administrator sheet](TEAM_LAN_ADMIN_CHEATSHEET.md).
