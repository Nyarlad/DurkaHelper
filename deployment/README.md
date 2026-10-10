# Deployment kit

English | [Русский](README-RU.md)

Use `durka.py` for normal operation. It connects the maintained S4DFarm/Neo/Packmate deployment, generates private credentials and handles internal image IDs/checksums automatically.

## Configure and start

```bash
python3 durka.py init
```

Edit `local/durka.json`: Ethernet bind, competition teams, flag format, receiver/token and Packmate service-side IP. Then prepare while connected:

```bash
python3 durka.py setup
python3 durka.py up
python3 durka.py status
```

`setup` fetches the pinned sources/images and builds the four maintained source components. `up` starts the farm, Neo coordinator and Packmate FILE UI. It starts neither submission nor Neo execution.

```bash
python3 durka.py worker
python3 durka.py submit
```

Enable the worker after preparing trusted scripts/dependencies. Enable submission after checking the competition adapter/receiver. Only `ructf_http` is maintained; this does not select the protocol for an unknown competition.

## Change event settings

For changed LAN addresses, team maps, submission settings or Packmate service IP, stop the stack, edit the local config, apply configuration, then start again:

```bash
python3 durka.py down
python3 durka.py configure
python3 durka.py up
```

Edit `local/durka.json` between the first and second command. This preserves data and uses cached images; it does not rebuild/download. Platform or credential replacement needs separate preparation.

## Traffic and shutdown

```bash
python3 durka.py traffic import /path/to/closed-capture.pcap
python3 durka.py down
```

Import replaces a **closed** PCAP, preserves the previous file and restarts only Packmate. Register the service/pattern and click the yellow downward-arrow processing button once in its UI. `down` retains data and images.

On Apple Silicon the current Packmate image uses amd64 emulation. Shared LAN and performance must be checked on the intended machine. For permitted Linux LIVE and manual capture, see [traffic capture](../docs/traffic-capture.md). Ordinary Docker Desktop deployment is FILE-only.

## Advanced tools

These remain available for dedicated operations, automation and troubleshooting; they are not extra onboarding steps:

| Script | Purpose |
|---|---|
| `toolkit.py` | Preview/prepare/build/preflight/start/stop the maintained deployment directly |
| `packmate_file.py` | Bounded PCAP replacement, prior-file retention and app-only restart |
| `packmate_host.py` | Approved native Linux host-interface LIVE |
| `packmate_live.py` | Approved existing Linux container-namespace LIVE |
| `recovery.py` | Native stack backup, verification and isolated database restore |
| `recovery_activation.py` | New application candidate restore/check/activation |

Direct mutating scripts have explicit `--apply`/confirmation flags; use their help for the operation's exact inputs. They never perform a host-wide prune.

<a id="native-backup-and-quarantine-restore"></a>
## Backup and recovery

Backups for this stack contain secrets and native database/state data; keep them outside Git and broadcasts. Use an exclusive maintenance window and a recoverable machine snapshot.

```bash
python3 deployment/recovery.py backup --help
python3 deployment/recovery.py verify --help
python3 deployment/recovery.py restore-native-stage --help
```

Backup pauses writers, dumps PostgreSQL natively, snapshots Redis and copies stopped Neo/Redis state. **The source stays quiesced**, including after an interrupted attempt. Restore creates new isolated storage; it does not overwrite the source. Retain images and input PCAP separately.

<a id="application-recovery-and-explicit-activation"></a>
## Application recovery

```bash
python3 deployment/recovery_activation.py recover --help
python3 deployment/recovery_activation.py verify --help
python3 deployment/recovery_activation.py activate --help
```

Application recovery consumes the verified backup/stage, restores PostgreSQL and Neo into a new candidate, checks authenticated startup/restart and leaves it stopped. **All candidate Redis queues/cache/sessions are discarded** to avoid replay; original RDBs stay in the backup. Do not use this policy if those values must be preserved.

Activation is separate from restore and starts no services. After acceptance, start only the chosen candidate, verify useful application scenarios and deliberately enable submission/worker. Never run the original and replacement on the same endpoints.

<a id="approved-linux-container-namespace-live"></a>
## Linux container-namespace LIVE

`packmate_live.py` serves an approved existing, running single-bridge container namespace on native Linux amd64 Engine. The owner/network need the expected capture ownership label and UI publication. It uses NET_RAW, not privileged mode; the database is reachable by peers on that bridge. It does not configure mirroring or general Vulnbox host capture.

Use `packmate_host.py` for an approved host/mirror interface instead. [Capture instructions](../docs/traffic-capture.md) explain the choice and exact profile. None of these launchers adds packet visibility to Docker Desktop.

[Administrator setup](../docs/MACOS_FULL_DEPLOYMENT_AND_TESTING.md) · [Admin cheat sheet](../docs/TEAM_LAN_ADMIN_CHEATSHEET.md)
