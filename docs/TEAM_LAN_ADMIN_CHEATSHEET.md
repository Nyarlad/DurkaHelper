# Administrator cheat sheet

English | [Русский](TEAM_LAN_ADMIN_CHEATSHEET-RU.md)

You host the shared farm, Neo coordinator and Packmate. Once configured, ordinary game operation needs these commands, not a validation form. Print this page and keep [workflows 01–05](ADMIN_WORKFLOWS.md) offline.

## Start

Start Docker Desktop/Engine and connect Ethernet. From the repository root:

```bash
DURKA_CONFIG=local/competition.json
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

Open the farm and Packmate URLs. Log in, then repeat from the separate PC or a teammate's device. The URLs use your actual Ethernet address; `localhost` is only for you. Set the variable in every terminal and select your actual prepared config. For changed event settings: stop native workers, down, edit this config, configure, then up; use the same --config.

## Share access

| Give teammates | Where it comes from |
|---|---|
| Farm URL and password | URL from `status`; `credentials.farm_password` in the selected private config |
| Neo host:port and key | Address from `status`; `credentials.neo_key` |
| Packmate URL, login and password | URL from `status`; `credentials.packmate_user / packmate_password` |
| Vulnbox/service access | The team's authorized service-access procedure |

Send credentials privately, separately from broadcast/screenshots. Do not share database passwords or Docker access. Participants use the [participant guide](participant-guide.md).

## Enable work

When scripts/dependencies are ready:

```bash
python3 durka.py --config "$DURKA_CONFIG" worker
```

When competition protocol, endpoint/token and team map are correct:

```bash
python3 durka.py --config "$DURKA_CONFIG" submit
```

The coordinator assigns tasks; workers execute and send matching stdout to Farm; Farm submits to the jury. The bundled worker is shell-only. Authors share a coordinator and use distinct task IDs: register disabled → wait for worker download → single → inspect → enable deliberately → disable. [Exact Neo examples](neo.md#one-shot-and-scheduled-harmless-example). QUEUED is not acceptance. Patches use the service's normal deployment.

## Traffic

For a closed PCAP:

```bash
python3 durka.py --config "$DURKA_CONFIG" traffic import /path/to/closed-capture.pcap
```

In Packmate, register the service/port/pattern and click the yellow downward-arrow processing button once. [Workflow 05](ADMIN_WORKFLOWS.md#workflow-05--packmate-live-or-file) covers LIVE doctor, offline bundle and deployment. Capture settings are in private local/packmate-remote.json; service ports/patterns are in the UI. Mac Ethernet alone does not provide visibility; FILE is not LIVE.

## Check the team

At home, use the Mac and a separate PC. At the event, repeat with every participating device:

- Log into farm and Packmate using the LAN URLs.
- Find the same known request/response in Packmate.
- Authenticate the Neo client, execute a harmless agreed script and confirm its result.
- Reconnect after a client interruption or scoped restart.
- Run normal workload; watch memory and disk.

No form is required. Fix failures before relying on that device/path.

## If something breaks

| Symptom | Check |
|---|---|
| All UIs unreachable | `status`, Ethernet IP/bind, Docker and published ports |
| Only one device fails | Its URL, route, credentials and client version |
| Flags wait in farm | Submission enabled? Correct adapter/token/expiry? |
| Neo scripts fail | Worker present? Interpreter/dependencies? Routes? |
| Packmate empty | Known traffic, correct service IP, registration and file/LIVE source |
| Disk grows rapidly | Stop incoming capture; retain needed files and prune only selected old private data |

Back up before risky changes. [Native stack recovery](../deployment/README.md#native-backup-and-quarantine-restore) pauses writers and restores to new storage; never copy live database files as ordinary backups.

## Finish

Stop new scripts/capture, retain backups, then:

```bash
python3 durka.py --config "$DURKA_CONFIG" down
```

Data and images remain. Avoid broad prune and `down -v`. [Full setup](MACOS_FULL_DEPLOYMENT_AND_TESTING.md).
