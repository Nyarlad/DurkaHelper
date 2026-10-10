# Administrator workflows

English | [Русский](ADMIN_WORKFLOWS-RU.md)

The practical route for one administrator and a trusted team. No evidence cards or manually copied hashes are required. Keep this checkout, its Russian pages and private dependencies available offline. [Printable quick reference](TEAM_LAN_ADMIN_CHEATSHEET.md).

## Roles and command conventions

DurkaHelper prepares and controls the stack. S4DFarm collects results and submits them to the jury. Neo's coordinator stores tasks and schedules execution; **workers execute them and send matching stdout values directly to the farm**. Participants use control clients connected to the same coordinator; they do not each need a worker. Packmate analyzes traffic. The scanner reviews local source copies; patches are applied manually through the service's own deployment mechanism.

Commands below run in the **DurkaHelper repository root on the administrator's Mac/Linux machine**, except the explicitly marked Neo terminal. Choose one config and use it on every stack command:

```bash
DURKA_CONFIG=local/competition.json
```

Set this variable again in each new terminal. `local/durka.json` is the CLI default and appears in older topic examples; do not accidentally operate a second deployment. Example addresses are documentation values, not working event targets. Read-only commands are `doctor`, `status` and `scan`; `init`, `setup`, `configure`, `up`, `worker`, `submit`, imports and `down` change private files or owned services. Never use global prune, Docker reset or `down -v`.

## Workflow 01 — Deploy and prepare offline

**Before:** approved Python 3.10+, Git 2.30+, Docker Desktop/Engine with Compose v2; sufficient disk and RAM; organizer's team map, service IPs, flag format, jury settings and permitted LAN address. First-time preparation needs Internet. Allow 30–60 minutes initially; about 5 minutes for a prepared start. [First Mac run](MACOS_FIRST_RUN.md) covers installation; [full guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md) is the reference.

For a new installation only:

```bash
python3 durka.py --config "$DURKA_CONFIG" init
```

Edit that private JSON in an editor. Preserve generated credentials. Set `profile.bind_address` to the administrator's actual LAN IPv4 for team/native-worker access; choose free `profile.ports.farm/neo/packmate`. Set `profile.farm.teams`, `flag_format`, `protocol_settings.SYSTEM_URL/SYSTEM_TOKEN`, `submit_limit`, `submit_period` and `flag_lifetime` from the organizers. Keep `protocol: ructf_http` only for the compatible HTTP interface. Set FILE `profile.packmate.local_ip` to the **service-side IP in captured packets**, not the administrator's address. Leave source/workspace paths and platform unchanged after preparation.

```bash
python3 durka.py --config "$DURKA_CONFIG" doctor
python3 durka.py --config "$DURKA_CONFIG" setup
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

`setup` downloads/builds pinned dependencies; do it before travel, not during an offline game. `up` uses prepared images and starts databases → Farm → Neo coordinator → Packmate. Worker and submission are separate opt-ins. Open the printed Farm/Packmate URLs, authenticate, check the team map and repeat from a second device. Internal databases are not team interfaces. Neo has no web dashboard. Share UI credentials and the Neo key privately, away from public screenshots.

**Already prepared:** skip `init/setup`. To apply organizer settings, stop the native worker and owned stack, edit the same JSON, then:

```bash
python3 durka.py --config "$DURKA_CONFIG" configure
python3 durka.py --config "$DURKA_CONFIG" up
python3 durka.py --config "$DURKA_CONFIG" status
```

`configure` requires a stopped stack and cannot change credentials, platform or storage layout. If its update fails, keep the stack stopped and use `configure --rollback`. If LAN fails, check actual bind/IP, ports and approved application firewall settings; do not disable network security globally.

**Offline checkpoint:** retain the source cache, Docker images/data, private config/workspace, compatible Neo binary and every script dependency. Prepare the separate Linux LIVE bundle in Workflow 05. Using a permitted arrangement with Internet absent but required LAN intact, run `down`, `up`, `status`; authenticate both UIs, run a harmless Neo task, scan a local copy and import a closed PCAP. This proves restart on the prepared machine, not installation on a blank machine. [Offline preparation and clean event state](offline-bundles.md).

## Workflow 02 — Scan, patch and verify

**Before:** an authorized local source copy, service startup/checker procedure and rollback owner. Run from the repository root; allow 10–30 minutes per small patch, depending on the service.

```bash
python3 durka.py scan /path/to/service --patches
```

Exit `1` means review findings; `2` means incomplete/invalid input. Read the linked remediation, confirm applicability and preserve original changed files plus a consistent native database backup when needed. Apply one minimal patch **manually**. Run the service's regression tests, normal login/read/write scenarios, old-data checks and actual competition checker; repeat the scan. A clean scan or `/health` alone is insufficient. No generic restart command exists for every Vulnbox: use the supplied service mechanism, not the toolkit's `down/up`.

If functionality regresses, restore previous code/image while preserving current game data. Do not restore an old database over new-round records. [Patch validation](patch-validation.md) gives detailed checks; its advanced `patch-check` records are optional for this manual route. [Backup/recovery](../deployment/README.md#native-backup-and-quarantine-restore) applies to the toolkit stack, not every protected service.

## Workflow 03 — Prepare scripts and Neo execution

**Before:** compatible Neo v2.4.2 client, private config with actual coordinator host/key, agreed task IDs and allowed team list. Every worker needs the script's actual interpreter, packages, auxiliary files and routes to both Farm and permitted services. The bundled light worker supplies shell, not arbitrary Python/Sage packages. Allow 10–15 minutes for the first harmless task. [Neo installation and complete examples](neo.md).

In a **separate terminal**, a shell-only worker can be started from the repository root:

```bash
python3 durka.py --config "$DURKA_CONFIG" worker
```

Alternatively, in the extracted **Neo client directory**, start one prepared native worker; do not start both merely to administer tasks:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1 --endless-jobs 0
```

Use a private client config with a unique worker `client_id` and valid task directory. A generated clean deployment's `config/neo-native.yml` can be used with the prepared binary instead; after a LAN change update its host or pass `--host LAN_IP:NEO_PORT`. Outside workers cannot use the container-only Farm hostname from a loopback profile.

In the author's **Neo client directory**, create the harmless `exploits/ready.sh` from the Neo guide, then:

```bash
chmod u+x exploits/ready.sh
./neo --verbose=false --config client_config.yml add --id ready-author-a --disabled --interval 1m --timeout 3s exploits/ready.sh
./neo --verbose=false --config client_config.yml single ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
```

Wait for the worker to download the new task and restart its execution loops before `single`. Expected: `worker ready for ...`, not a flag. `single` covers **all configured teams**, without enabling recurrence. Each author uses a distinct shared ID. After a successful permitted single run, deliberately test scheduling:

```bash
./neo --verbose=false --config client_config.yml enable ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
./neo --verbose=false --config client_config.yml disable ready-author-a
```

Observe subsequent one-minute runs before disabling. No cron is needed; closing the control client does not disable a task. Stop a native worker with Ctrl+C after disabling future work; already running jobs may finish. For failures, first check worker presence/download, interpreter and routes. Avoid raw `neo info` or debug logs on screen: they may disclose credentials.

## Workflow 04 — Farm and jury submission

**Before:** approved jury endpoint/token, exact flag regex, lifetime and rate limits; a legitimate synthetic or organizer-provided test value. Allow 5–10 minutes. Do not enable against placeholders. [Farm reference](s4dfarm.md).

ForcAD's compatible interface uses **HTTP PUT `/flags`**, a JSON array of flags and the `X-Team-Token` header. Configure the full organizer-provided URL and private token via Workflow 01; do not assume the path, limits or token from another event. The maintained adapter is `ructf_http`; another protocol requires separate validation, not an untested adapter substitution.

Confirm the worker's permitted test output appears in Farm, then enable submission from the repository root:

```bash
python3 durka.py --config "$DURKA_CONFIG" submit
```

`QUEUED` proves ingestion only. Verify the final status **and receiver response**, plus jury/scoreboard confirmation where provided. Use a controlled synthetic jury to check invalid, duplicate and expired results; do not mass-resubmit to a real event. Farm deduplication may suppress a second identical value before any HTTP request. `SKIPPED` can be local queue policy, not a ForcAD response. If queued indefinitely, check enabled submission, endpoint/token, lifetime, rate limits and worker-to-Farm reachability. Never print tokens during diagnostics.

To stop submission safely, disable future Neo tasks, stop native workers and run the selected stack's `down`. Restart with `up`; submission must be explicitly enabled again. Review restored queues before enabling: expired recovered data must not be replayed blindly.

## Workflow 05 — Packmate LIVE or FILE

**Before:** an authorized traffic source. A Mac on ordinary Ethernet does not see all Vulnbox traffic. FILE is closed-file analysis, **not continuous LIVE**. Allow 10–20 minutes for a prepared Linux LIVE deployment; 3–5 minutes per FILE import. [Traffic choices](traffic-capture.md) and [remote LIVE instructions](packmate-remote.md).

On the administrator's machine, while online, prepare the **separate Linux AMD64 image pair** once. A Mac's ARM64 database image is not a substitute:

```bash
python3 durka.py traffic live bundle --output local/packmate-live-ready --download --apply
```

Keep an already successful bundle; this command requires a new output path. Target Python is not required. Linux LIVE needs rootful Docker/Compose, verified SSH identity, an explicitly permitted **whole interface**, and approval for host networking + NET_RAW. No privileged container, NET_ADMIN or Docker socket mount is required. First run read-only discovery, using the actual authorized host/key:

```bash
python3 durka.py traffic live doctor --host example@vulnbox.example --key ~/.ssh/ctf_capture
```

Use `--docker /absolute/approved-wrapper` only if ordinary `docker` is unavailable to that user; passwordless sudo is not automatically selected. No permission/firewall changes are made by doctor. Verify the SSH fingerprint through a trusted channel. Then initialize a new private target config using actual doctor results:

```bash
python3 durka.py traffic live init --host example@vulnbox.example --key ~/.ssh/ctf_capture --remote-dir /home/example/durka-packmate-live --interface eth0 --service-ip 192.0.2.10 --bind 192.0.2.20 --ui-port 65000 --db-port 55432
```

**Configuration happens here, before `up`:** edit `local/packmate-remote.json` if necessary. Its `profile` holds interface, service-side IP, Linux UI bind/ports, TCP/UDP timeouts and retention. `bind` is an address assigned to Linux, not the Mac. The database is loopback-only. Service **names, ports and search patterns are registered separately in the Packmate UI**. Do not edit generated application properties/Compose files. Editing JSON after deployment does not reconfigure the running installation; see the remote guide before creating a replacement.

```bash
python3 durka.py traffic live doctor --bundle local/packmate-live-ready
python3 durka.py traffic live up --bundle local/packmate-live-ready --apply --host-network-approved --interface-scope-approved
python3 durka.py traffic live status
```

This transfers and loads prepared images without target Internet, then starts only the owned project. It changes remote private files/containers and uses approved capture privileges. Open its printed URL, authenticate using the private config; on Mac `traffic live password` copies the password without printing it. Register both services' real ports. Produce a normal known request: verify its request/response, service-side direction, timestamps and checker health, then test capture restart using scoped `down --apply` / `up ...`. Retention limits age, not hard disk capacity; watch disk usage. Readiness/authentication PASS alone does not prove captured traffic.

For FILE, obtain a **closed** PCAP through the permitted capture/transfer procedure. On the administrator's repository checkout:

```bash
python3 durka.py --config "$DURKA_CONFIG" traffic import /path/to/closed-capture.pcap
python3 durka.py --config "$DURKA_CONFIG" status
```

Select/register the service in the local Packmate UI and click the **yellow downward-arrow processing button** once; do not look for a Start or Load PCAPs label. Wait for processing, find the known request and matching response, then repeat with another closed file. The import retains the previous file and restarts only Packmate. Empty results: check service IP, port/pattern, known marker, processing state and stream timestamps; do not assume a time-filter UI exists. Packmate uses AMD64 emulation on Apple Silicon; measure latency locally.

**Shutdown/recovery:** stop new input, preserve required private data, run `traffic live down --apply` for that configured Linux capture only; run `durka.py --config "$DURKA_CONFIG" down` for the local stack. Both retain persistent data/images. Never delete live database files. If LIVE is forbidden or has no traffic visibility, use FILE as a fallback and label continuous capture unavailable. [Native recovery and quarantined restore](../deployment/README.md#native-backup-and-quarantine-restore) and [offline guide](offline-bundles.md) cover recovery; test restore separately before relying on it.

## Final operator checks

Authenticate each participating device; exercise a useful UI action and reconnect. Verify each actual script environment, Farm-to-jury acceptance, authorized LIVE or closed FILE flow, offline restart under normal load. Event routes, capture permission and organizer settings require event-specific verification. Linux tests and hosted macOS CI do not prove Docker Desktop, team LAN or local policy compatibility. Keep unperformed checks **NOT TESTED**, not ready.
