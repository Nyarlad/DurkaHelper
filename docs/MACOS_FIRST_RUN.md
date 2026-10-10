# First Mac run

English | [Русский](MACOS_FIRST_RUN-RU.md)

This is the short operator route, not a claim that this machine is ready. All Mac runtime steps below are **PENDING real-Mac acceptance**. Run them only after approval for Docker Desktop, local services, Ethernet access. Installation details, configuration fields and backup procedures live in the [full guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md).

## 1. Read-only preflight

From the repository root, using native ARM64 Python:

```bash
python3 durka.py doctor
```

`doctor` does not install, download, pull, build, start services, change configuration or execute Neo. It checks the actual macOS/architecture, Python 3.10+, Git 2.30+, local Desktop Engine, Compose v2+, resources, configured ports and prepared runtime images. It never prints credentials or listener names. `READY` applies to the named check, not the whole competition.

Exit codes: `0` all checks ready; `1` warnings/unverified checks; `2` a blocker. Missing config/images/client before setup is expected. Packmate emulation remains a warning, and offline/LAN acceptance remains `NOT VERIFIED` even when cached images match. Occupied ports may belong to your already-running stack; do not kill another process to clear a warning.

If Python/Git are absent, prepare them using approved installers first. Check the actual macOS and Docker Desktop versions against the approved installation requirements; a previously reported version is not evidence. Start Desktop manually after approval. Start with 4 CPUs / 8 GiB RAM and a 96 GiB disk budget, then measure rather than assume performance.

## 2. First setup while online

This step writes private configuration and prepares dependencies. Keep the config/passwords private.

```bash
python3 durka.py init
```

Edit `local/durka.json`: keep `bind_address` at `127.0.0.1`, choose the Darwin ARM64/Desktop profile, FILE mode and `profile.packmate.local_ip` set to `192.0.2.20` for the synthetic capture below. Keep the example farm submission URL/token; **do not run `submit`**. The farm's maintained adapter is `ructf_http`, not an assertion about any event's protocol. Other protocols require separate compatibility validation.

After approval, with Internet available:

```bash
python3 durka.py setup
```

Prepare the locked Neo **v2.4.2 Darwin ARM64** client using [Neo installation](neo.md). Put its executable at `local/neo-client/neo`, or pass its actual path to `doctor --neo-client PATH`. Keep the release/config/task directory available offline. Doctor checks an executable Mach-O ARM64 header; it does not authenticate the client or prove its version. Use only the locked release, not an arbitrary binary with a matching header.

## 3. Start and check the tools

```bash
python3 durka.py doctor
python3 durka.py up
python3 durka.py status
```

Order is handled by the kit: databases → S4DFarm → Neo coordinator → Packmate. Worker and competition submission remain disabled. Expected: services are running and Farm/Packmate addresses are printed. Neo is a script coordinator, not a web dashboard. Farm collects flags; it does not deploy patches. Packmate FILE searches a closed capture, not live LAN packets.

Log in to Farm using the private config and confirm its team/config view. Startup already authenticates `/api/get_config`; a login screen alone is not an API test. Log in to Packmate. Never print `neo info`, expanded Compose config or raw logs on a broadcast.

## 4. Synthetic end-to-end checks

Generate a new closed capture with the existing fixture, then import it. These commands write only a local synthetic file and change this deployment's Packmate input; previous input/data are retained.

```bash
python3 -c 'from integration.synthetic_pcap import make_pcap; from pathlib import Path; p = Path("local/first-run.pcap"); f = p.open("xb"); f.write(make_pcap("0123456789abcdef01234567")); f.close(); p.chmod(0o600)'
python3 durka.py traffic import local/first-run.pcap
python3 durka.py scan lab --patches
python3 scripts/defense_ops.py preflight --profile config/defense-profile.example.json
python3 integration/vulnbox_handoff.py
```

In Packmate add service port **18080**, a substring pattern `0123456789abcdef01234567`, then press the yellow downward-arrow FILE-processing button in the sidebar once; do not look for a literal "Start" label. Find the GET `/durkahelper-smoke/…` and response `DURKAHELPER_RESPONSE_…`, with correct directions. Scanner findings on the deliberately vulnerable lab mean expected exit `1`, not installation failure; Defense preflight and handoff should exit `0`/report PASS.

Use the [harmless Neo readiness task](neo.md#first-harmless-task), then explicitly start `python3 durka.py worker` and run that disabled task once. Expect the readiness message in its bounded `tail`; no target request and no accepted flag. The selected worker image must contain the script's actual dependencies: the default light image is not a generic Python/Sage environment. Stop the worker with the deployment when finished.

The [isolated complete-stack procedure](../integration/README.md#release-candidate-acceptance) additionally checks synthetic Neo→Farm→mock receiver, auth failures, native restore and known Packmate payloads. It is a Linux AMD64 fixture, not proof about Desktop or the native Darwin client. Do not point it at your operator workspace or real submission endpoint.

## 5. Offline, restart and workload rehearsal

Keep Ethernet/LAN but disconnect Internet using an approved arrangement. Do not reset Desktop or prune images. Cold-start the prepared services:

```bash
python3 durka.py down
python3 durka.py up
python3 durka.py status
```

Expected: no downloads/builds; Farm settings, disabled Neo task and Packmate service/pattern/previous streams persist. FILE parsing does not automatically resume: press the FILE-processing button only when intentionally processing the current capture. Repeat the harmless Neo task after explicitly starting the worker. New PCAP imports are deliberate replacements, not an endless FILE pipe. Follow [offline operation](offline-bundles.md) and [native backup/recovery](MACOS_FULL_DEPLOYMENT_AND_TESTING.md) before adding valuable data; retaining a directory is not a backup.

Run the prepared stack under normal workload for at least 60 minutes; check responsiveness, disk growth, memory pressure and repeated PCAP imports. Hosted macOS CI does not prove Docker Desktop, LAN or local policy compatibility.

## 6. Failures and safe shutdown

On failure stop progressing: `status`, then `doctor`; use the [troubleshooting guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md). A config edit after setup needs `down` → edit → `configure` → `up`; interrupted configuration may require `configure --rollback`. Missing images must be prepared while online, not fixed mid-game. A wrong-architecture client must be replaced with the reviewed client, not run through an unplanned workaround.

```bash
python3 durka.py down
```

This stops only the owned deployment, including its worker, retaining data and images. Do not use `down -v`, global `prune`, broad deletion or Desktop reset. Native dumps or a consistent stopped copy must be restored into a new isolated environment, never over live database files.

## Remaining manual gates

- Real Mac: approved installation, native client authentication/execution, complete-stack Desktop checks, offline startup, recovery load.
- Home Ethernet rehearsal: Mac plus a second PC must authenticate and perform useful Farm/Neo/Packmate actions, then reconnect after restart; localhost/TCP connect alone is insufficient. Use the [admin cheat sheet](TEAM_LAN_ADMIN_CHEATSHEET.md).
- Event-only: repeat participant access and checker availability using the offline [game-day checklist](game-day.md). No AI or code changes should be required.
- Capture: prepare both [approved Linux LIVE and closed-PCAP transfer](traffic-capture.md). A Mac on the switch does not automatically see Vulnbox traffic. FILE fallback alone does not satisfy a continuous-capture requirement.
- Protocol: validate the actual competition adapter before enabling real submission; keep replay of recovered queues disabled until reviewed.
