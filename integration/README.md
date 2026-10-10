# Synthetic integration tests

English | [Русский](README-RU.md)

These are developer fixtures, **not the deployment instructions**. For a working team stack use [durka.py and the admin guide](../deployment/README.md).

## Isolation and prerequisites

Opt-in Docker tests run only in a dedicated private workspace with synthetic credentials/data. Use an approved Linux Docker Engine, cached locked images, unique project names and available resources. Recovery and fault-injection runs require a host snapshot. They do not inspect unrelated workloads.

## Prepare and run

Read a fixture's help, preview preparation, then apply it deliberately. Profiles cannot contain shell commands. Run from the repository root. Results stay in the chosen private workspace, not in Git.

```bash
python3 integration/stack_smoke.py --help
python3 integration/packmate_smoke.py --help
```

## Rollback and failures

Use the fixture's own shutdown; never global prune or deletion of shared volumes. Failed runs retain local results/data for diagnosis. Review exact-resource cleanup before retrying in a fresh workspace.

## Evidence boundaries

A synthetic test is not a certification of Docker Desktop, event capture or real participant access. CI run logs and private run outputs replace committed historical report files. See [capabilities and limits](../docs/CAPABILITY_INVENTORY.md).

## Packmate FILE-only fixture

`packmate_smoke.py` tests closed synthetic PCAP import, authentication and known streams. It cannot establish continuous capture.

## Native PostgreSQL recovery drill

`recovery_smoke.py` checks native dump/restore into isolated databases. Never substitute live competition volumes for its synthetic inputs.

## Published Neo release client

`neo_release_smoke.py` verifies the pinned published client against the pinned server; it does not silently select latest.

## Harmless Neo task lifecycle

`neo_lifecycle_smoke.py` exercises a harmless task, result, reconnect and disable sequence. Workers execute trusted code; do not feed them arbitrary tasks.

## Native Redis recovery

`component_recovery_smoke.py` checks native persistence and recovery in an isolated fixture. Real submission queues need a separate replay decision.

## Packmate authentication logger canary

`packmate_logger_smoke.py` verifies the configuration-only suppression of the failed-auth logger against a disposable canary and positive control. It does not certify every possible log path.

## Whole-stack synthetic recovery

`stack_recovery_smoke.py` restores synthetic farm, Neo and Packmate state into new projects, keeping automatic submission disabled. This is not permission to overwrite an existing deployment.

## Synthetic LIVE capture

`packmate_live_smoke.py` observes only its synthetic Linux network/namespace. It tests TCP/UDP, timeout and restart behavior, not real Vulnbox visibility or sustained load.

## Network-isolated offline runtime rehearsal

`offline_runtime_smoke.py` cold-starts an isolated Linux stack from prepared images and checks network denial plus retained synthetic state. It does not install a complete toolchain on a clean laptop. For normal offline preparation see [offline operation](../docs/offline-bundles.md).

Individual fixtures expose their arguments through `--help`; guarded low-level flags are for developers, not forms an ordinary operator must fill.

## Portable synthetic Vulnbox handoff

`vulnbox_handoff.py` retrieves a small closed synthetic PCAP over loopback HTTP,
validates its framing, rejects truncation, and exercises Docker source review
before and after fixture-only manual edits. It never starts privileged containers.
The macOS workflow accepts an optional bounded synthetic PCAP as base64 input;
otherwise it generates one locally. Do not supply real traffic or secrets.
This tests portable file handling and scanner commands, **not** direct VM access,
Packmate processing, LIVE visibility or Docker Desktop. Test those separately on
an approved Linux host and the actual Mac.

## Release-candidate acceptance

One sequence reuses the fixtures above; no second infrastructure is introduced. **Prepared procedure, not a newly executed runtime result.** Run from the repo root on an approved, non-root **native Linux AMD64** Docker host. It is not the first Mac installation; that route is [First Mac run](../docs/MACOS_FIRST_RUN.md). Desktop/emulated execution of these Linux fixtures is NOT VERIFIED. The published release probe uses the Linux client, not the native Darwin client.

Prerequisites: locked, clean checkouts at `local/sources/s4dfarm`, `local/sources/neo`, `local/sources/packmate`; cached Linux AMD64 images from the integration/deployment locks; the locked Linux Neo archive at `local/downloads/neo_client_2.4.2_linux_amd64.tar.gz`. Preparing/building dependencies requires a separately approved online phase. Do not substitute an operator/competition workspace. Missing prerequisites mean BLOCKED, not permission to fetch latest.

Run commands in order and stop at the first nonzero result; every applied fixture should report PASS. A scanner finding in the vulnerable lab is the exception (expected `1`). Workspace/project IDs and synthetic markers are generated automatically; do not fill evidence cards or copy hashes manually. Only the generated internal mock receiver receives synthetic flags; **real flag submission remains disabled**.

```bash
set -euo pipefail
umask 077
mkdir -p local
RC_RUN="$(mktemp -d "$PWD/local/rc-acceptance.XXXXXX")"
PM_DB="$(python3 -c 'import durka; print(durka.kit.PACKMATE_DB)')"
python3 integration/stack_smoke.py prepare --workspace "$RC_RUN/stack" --s4dfarm-source local/sources/s4dfarm --neo-source local/sources/neo --images config/integration-images.lock.json --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py build --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py prepare --workspace "$RC_RUN/packmate" --source local/sources/packmate --postgres-image "$PM_DB" --apply --approval-id rc-synthetic
python3 integration/neo_release_smoke.py prepare --workspace "$RC_RUN/client" --archive local/downloads/neo_client_2.4.2_linux_amd64.tar.gz --apply --approval-id rc-synthetic
python3 integration/neo_lifecycle_smoke.py prepare --workspace "$RC_RUN/task" --apply --approval-id rc-synthetic
```

The build may download compiler/package dependencies; finish it **before** the offline phase. Cached base images alone are insufficient. These fixture paths, sources and API semantics are guarded by the existing scripts. No LIVE capture, privilege, host networking or real target is needed.

```bash
python3 integration/stack_smoke.py up --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py smoke --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/neo_release_smoke.py smoke --workspace "$RC_RUN/client" --stack-workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/neo_lifecycle_smoke.py smoke --workspace "$RC_RUN/task" --release-workspace "$RC_RUN/client" --stack-workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py up --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 integration/packmate_smoke.py smoke --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 integration/vulnbox_handoff.py
```

Expected: Farm authenticated API/config and rejection of missing/wrong auth; Neo exact release auth, disabled-first harmless `printf`, single execution, farm/mock-receiver acceptance and worker reconnect; Packmate auth, one synthetic stream with exact request/response/directions; Defense CLI and source review/manual fixture-patch comparison. Worker tests only prove their shell dependencies, not arbitrary Python/JS scripts. Do not rerun fresh-database Packmate smoke on already processed data; persistence is checked separately below.

Cleanly stop the templates first to limit resource overlap; data/images stay in their private directories:

```bash
python3 integration/packmate_smoke.py down --workspace "$RC_RUN/packmate" --apply --approval-id rc-synthetic
python3 integration/stack_smoke.py down --workspace "$RC_RUN/stack" --apply --approval-id rc-synthetic
```

After confirming a snapshot of this test host, run recovery into **new** synthetic projects. Never pass `--snapshot-confirmed` without an actual snapshot. No existing operator data is copied. Automatic submission/capture replay stays disabled in restored targets.

```bash
python3 integration/stack_recovery_smoke.py prepare --workspace "$RC_RUN/recovery" --stack-workspace "$RC_RUN/stack" --packmate-workspace "$RC_RUN/packmate" --release-workspace "$RC_RUN/client" --apply --approval-id rc-synthetic
python3 integration/stack_recovery_smoke.py run --workspace "$RC_RUN/recovery" --apply --approval-id rc-synthetic --snapshot-confirmed
```

Expected: settings, synthetic flags, disabled Neo task/state, Packmate services/patterns/streams preserved through controlled stop, native dumps/cold copies and isolated restore. `result.json` records timing (targets: RPO 300s / RTO 600s), all checks and scoped shutdown. Data/backups remain. A FAIL/PARTIAL/BLOCKED or unsuccessful cleanup prevents acceptance.

For full **offline startup**, reuse `offline_runtime_smoke.py`, not the network-capable build fixture. Set `RC_TEMPLATE` to an already prepared native Linux AMD64 synthetic deployment from `deployment/toolkit.py` (never a competition workspace), and `RC_IMAGES` to its verified complete private image bundle. Use the existing [offline cache utilities](../docs/offline-bundles.md); all runtime/helper images must be present. No bundle means offline acceptance remains BLOCKED. Keep the host snapshot and approved local Docker context.

```bash
RC_DAEMON="$(docker info --format '{{.ID}}')"
python3 integration/offline_runtime_smoke.py prepare --workspace "$RC_RUN/offline" --template "$RC_TEMPLATE" --image-bundle "$RC_IMAGES" --daemon-id "$RC_DAEMON" --apply --approval-id rc-synthetic
python3 integration/offline_runtime_smoke.py run --workspace "$RC_RUN/offline" --apply --approval-id rc-synthetic --snapshot-confirmed
python3 integration/offline_runtime_smoke.py down --workspace "$RC_RUN/offline" --apply --approval-id rc-synthetic
```

Expected: prepared immutable images only, denied external networking in owned test resources, full synthetic Farm/Neo/Packmate cycle, restart/persistence and clean scoped shutdown. It does not alter host/router networking or prove a blank-laptop installation. On Mac, perform the separate disconnected Desktop rehearsal in the first-run guide.

If a phase fails, stop only the exact owned project using its fixture's `down`. Recovery/offline fixtures record automatic cleanup; if that fails, inspect their private result and exact labelled resources before retrying. Never `prune`, `down -v` or remove the run directory as a substitute for cleanup. Retain outputs privately; do not commit logs/PCAP or declare target-Mac readiness from Linux PASS.
