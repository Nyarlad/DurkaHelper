# Set up and run the team tools on macOS

English | [Русский](MACOS_FULL_DEPLOYMENT_AND_TESTING-RU.md)

This is the administrator's route from checkout to a usable team stack. Participants use the [participant guide](participant-guide.md). All commands below run from the DurkaHelper repository root.

For the first deployment, follow the shorter [first-run procedure](MACOS_FIRST_RUN.md), starting with read-only `python3 durka.py doctor`. This full guide is the configuration/recovery reference, not proof of a completed real-Mac rehearsal.

## 1. Know the layout

DurkaHelper runs natively in Python. Docker Desktop runs S4DFarm, the Neo coordinator/worker and Packmate FILE. Protected services stay on the Vulnbox over Ethernet. The laptop hosts tools, not the protected service deployment.

Farm = flags and submission. Neo = script distribution/execution. Packmate = traffic analysis. Scanner = local source review. [Connection diagram](team-setup.md).

## 2. Install prerequisites

Install Git, Python 3.10+ and Docker Desktop through the software source permitted on your machine. Start Docker Desktop and check:

```bash
uname -m
python3 --version
git --version
docker version
docker compose version
```

Apple Silicon should report `arm64`. Packmate's retained image is amd64-only, so this stack uses Docker Desktop's amd64 emulation. A starting resource budget is 4 CPUs, 8 GiB RAM and 96 GiB Docker disk; adjust after measuring your workload. Have enough host disk for PCAP and backups.


## 3. Clone and configure

```bash
git clone https://github.com/Nyarlad/DurkaHelper.git
cd DurkaHelper
python3 durka.py init
```

Open `local/durka.json` in your editor. Passwords/key are already generated. Change these values:

| Setting | Put here |
|---|---|
| `profile.bind_address` | Your Ethernet IPv4 for team access; keep `127.0.0.1` only for a laptop-only rehearsal |
| `profile.ports` | Farm 8080, Neo 5005 and Packmate 65000 by default; change only if occupied |
| `profile.farm.teams` | Competition team names and actual service/Vulnbox addresses |
| `profile.farm.flag_format` | Organizer's flag regex |
| `profile.farm.protocol_settings` | Submission URL/token from the competition |
| `profile.farm.submit_limit / submit_period / flag_lifetime` | Competition limits and timing |
| `profile.packmate.local_ip` | The service-side IP represented in your PCAP |
| `credentials` | Generated farm password, Neo key and Packmate login/password; distribute only the needed values |

Native teammate workers require the actual Ethernet bind: the coordinator advertises that LAN farm URL to them. A loopback demo supports only the in-stack worker's internal farm route.

The current adapter is `ructf_http`. Do not enable submission for a different protocol until it has a compatible adapter. You can start the tools and inspect traffic while submission remains off.

`local/` holds private configuration, downloaded sources, deployment data and incoming captures. Keep it out of Git. For a home rehearsal, submission settings can stay as examples while submission remains off.

At the event, stop the stack, edit the LAN/team/submission/Packmate settings, apply configuration and start. Data/images remain; no download or rebuild is needed:

```bash
python3 durka.py down
python3 durka.py configure
python3 durka.py up
```

Edit `local/durka.json` between `down` and `configure`. Changing platform or credentials is separate preparation.

## 4. Prepare while Internet is available

```bash
python3 durka.py setup
```

This fetches the exact source versions, pulls pinned images, prepares the private workspace and builds the farm/Neo components. It can take several minutes. Version and image checks run automatically; no manual checksum copying is required.

Do this on the machine you will use. A Linux amd64 cache does not contain native Mac prerequisites or establish Apple Silicon performance. Keep Docker Desktop, Python, the repository, cached images, the Neo client and your scripts/dependencies available before disconnecting.

## 5. Start and check access

```bash
python3 durka.py up
python3 durka.py status
```

Start includes farm UI/API, Neo coordinator and Packmate UI. It creates an empty PCAP so the UI can start before the first capture. Submission and the worker remain off.

Open the farm and Packmate URLs printed by `status`; log in with values from your private config. Then open those same LAN URLs from another physical machine. `localhost` on a teammate's machine points at that teammate, not at your laptop.

Give teammates only the farm URL/password, Packmate URL/login and Neo address/key they need. Database/Redis/Docker endpoints are not shared. If macOS asks about incoming connections, permit the relevant application under your allowed policy; do not disable the firewall.

## 6. Traffic and scripts

For the initial Mac route, obtain a closed authorized PCAP and import it:

```bash
python3 durka.py traffic import /path/to/closed-capture.pcap
```

Open Packmate, register the service and search pattern, then start processing once. Find a known request and response. For repeated files, use the same import command. It replaces the active file while preserving the previous one. Full options, Linux/Vulnbox LIVE and bounded manual capture are in [traffic capture](traffic-capture.md).

For team script execution, install a compatible Neo v2.4.2 client on each script writer's machine and follow [Neo](neo.md). When scripts are ready, start the administrator's worker:

```bash
python3 durka.py worker
```

The bundled light worker has a shell, not a complete Python/Sage environment. Add compatible workers with your actual script dependencies before relying on them. Workers need routes to the coordinator, farm and permitted service targets.

## 7. Enable submission and defend

After checking the real adapter, endpoint, flag format and team map:

```bash
python3 durka.py submit
```

Watch accepted/rejected/expired statuses in the farm. A reachable UI does not prove the competition accepts flags.

For each service, copy source from the Vulnbox to your private working directory and scan:

```bash
python3 durka.py scan /path/to/service --patches
```

Review the linked fix recipe, back up the original, apply a small patch on the Vulnbox and verify availability/checker behavior. Rerun the source scan. The scanner reads files; it does not SSH into targets, execute their code or deploy a fix.

## 8. Rehearse offline and with load

At home, use the Mac and a separate PC on wired LAN: log in to farm/Packmate, connect Neo, import known traffic, run one harmless script and reconnect after a scoped restart. Then disconnect Internet while keeping LAN and repeat startup/use.

Run the tools under normal workload for at least 60 minutes. Watch Docker memory, CPU, PCAP/database growth and available disk. At the event, repeat the access test on each teammate's device and choose the prepared permitted capture path.

## 9. Backup, stop and recover

`down` stops this deployment and retains its data/images. It is not a backup. Before a risky service patch, retain that service's original files and use its database's native dump procedure.

For the shared maintained FILE stack, [native backup and recovery](../deployment/README.md#native-backup-and-quarantine-restore) uses native database dumps and a new isolated restore. Backup intentionally pauses the source. Recovery resets the new candidate's Redis queues/cache/sessions to prevent replay; use that procedure only when this loss is acceptable.

```bash
python3 durka.py down
```

Stop script activity/capture first; then stop the stack if applicable. Never use `docker compose down -v` or broad `docker system prune` as routine shutdown.

## 10. Common problems

| Symptom | Next action |
|---|---|
| Docker cannot connect | Start Docker Desktop, wait for Engine, rerun `status` |
| UI works locally, not from the PC | Correct Ethernet bind/IP, exact URL/port, macOS incoming-connection policy and allowed LAN path |
| Farm has flags but no submissions | Enable submission only after checking adapter, URL/token and expiry |
| Neo task fails | Check worker presence, interpreter/dependencies and target routes |
| Packmate is empty | Correct service-side IP, service/pattern registration, closed capture and known traffic |
| Apple Silicon is slow | Check emulation and Docker resources; reduce capture volume/workload or use an allowed Linux capture node |
| Disk is filling | Stop new capture/import, retain needed data and remove only identified old private files |

For removal, run `down`, retain needed backups and then delete only your stopped `local/` deployment/source/data directories. Removing Docker Desktop or shared images is a separate machine administration task.
