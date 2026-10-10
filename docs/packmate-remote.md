# Packmate LIVE: deploy from the laptop over SSH

English | [Русский](packmate-remote-RU.md)

Run every command below **on the laptop, from the DurkaHelper repository root**.
Python is not required on the Vulnbox: the program transfers rendered configuration
and runs Docker Compose. This does not replace [FILE import](traffic-capture.md#file-on-the-laptop) on Mac.

## Requirements

- Laptop: Python 3.10+ and SSH; Docker is needed only to prepare image bundles.
  Bundle preparation requires Docker CLI/Engine API 1.49+ for explicit
  [platform selection](https://docs.docker.com/reference/cli/docker/image/inspect/).
- Traffic source: native Linux **amd64**, local rootful Docker Engine, Compose v2,
  `sh`, `tar`, `ip`, `ss`, `stat`, `df`, `sha256sum`, `cut`, `awk`.
- Working key authentication and a verified SSH host key. No automatic host-key
  acceptance. For a passphrase-protected identity, first run `ssh-add ~/.ssh/ctf_capture`;
  the program does not receive the passphrase.
- Approval for the **entire selected interface**, host networking and NET_RAW.
  No privileged containers, NET_ADMIN, Docker socket mounts or package installation.
- At least 3 GiB available RAM and 5 GiB free disk before startup. Combined limits
  are 2 CPU / 2 GiB RAM. Age cleanup is not a hard storage quota.

Unmodified upstream Packmate briefly uses a broad TCP/UDP startup filter.
A Mac on an ordinary switch does not automatically see Vulnbox traffic. Placement
defines permitted traffic visibility; the program does not create mirroring or
manually change firewall/routes. Docker creates only this deployment's networks.

## 1. Read-only doctor, before configuration

Replace the example hostname and identity path. For an already approved Docker
wrapper, pass its absolute path using `--docker`; shell commands are not accepted.

```bash
python3 durka.py traffic live doctor \
  --host example@vulnbox.example --key ~/.ssh/ctf_capture \
  --ui-port 65000 --db-port 55432
```

Doctor reports Engine identity, architecture, interfaces/IPs, RAM/disk, Compose
and utility availability, cached amd64 images and the two requested ports.
**No target writes, downloads or startup.** PASS covers checked prerequisites, not
traffic visibility. WARNING for missing images requires an offline bundle. BLOCKED
means access/platform/resource/port issues; do not stop unrelated workloads.

## 2. Prepare offline images before the event

With laptop Internet access and Docker running:

```bash
python3 durka.py traffic live bundle \
  --output local/packmate-live-images --download --apply
```

This downloads **two pinned Linux amd64 images**, including on an ARM64 Mac. Omit
`--download` if both are cached. The output directory must be new. Keep `images.tar`
and the automatic manifest together; no manual SHA forms are required. An ARM64
PostgreSQL image from the Mac stack does not substitute for the amd64 image.
Inspection and archive export explicitly select Linux amd64, even when the
image cache also contains ARM64 variants; the running Mac stack is not changed.
Only local files and the image cache change; no containers start.
Do not commit image archives; review upstream licenses separately before public redistribution.

## 3. Create one private configuration

Replace example values using doctor results and event rules:

```bash
python3 durka.py traffic live init \
  --host example@vulnbox.example --key ~/.ssh/ctf_capture \
  --remote-dir /home/example/durka-packmate-live \
  --interface eth0 --service-ip 192.0.2.10 --bind 192.0.2.20 \
  --ui-port 65000 --db-port 55432
```

`--service-ip` is the protected service-side IP **in the captured traffic**;
`--bind` is the Linux host's assigned UI IP. They may differ. Interface index/MAC
and Engine identity are filled automatically. Only the local
`local/packmate-remote.json` is created, with generated passwords; the source is
unchanged. Never publish this private file. Init does not overwrite.
Use separate `--config` and `--remote-dir` for another deployment.

## Where the deployment configuration lives

On the laptop: `local/packmate-remote.json`, or the file selected by `--config`.
This is separate from the farm/FILE configuration. It contains passwords: keep
it private and out of Git. The `profile` section includes:

| Field | Purpose | Default at init |
|---|---|---|
| `interface` | Approved Linux capture interface | Selected through `--interface` |
| `local_ip` | Service-side IP in packets; determines direction | `--service-ip` |
| `bind_address`, `ui_port` | Linux web-interface address and port | `--bind`, port 65000 |
| `db_port` | PostgreSQL on IPv4 loopback only | 55432 |
| `tcp_timeout_seconds`, `udp_timeout_seconds` | Stream timeouts | 30 / 10 seconds |
| `timeout_check_seconds` | Timeout-check interval | 5 seconds |
| `retention_minutes`, `cleanup_interval_minutes` | Deletion age and cleanup interval | 60 / 1 minutes |

Application ports and search patterns are configured separately [in the UI](packmate.md#ui-services-and-patterns).
Linux `workspace/application.properties` and `runtime-compose.json` are generated
automatically from this configuration. Do not edit those files manually.

Choose addresses/ports/interface during `init`; tune `profile` timeouts and
retention **before the first up**, retaining mode 0600. Engine ID, interface
index/MAC, project and images are automatic checks, not settings to bypass a
doctor error. Do not rotate credentials independently of an existing database.

After deployment, configuration and runtime must match exactly. Editing local
JSON **does not update** running Packmate: this launcher has no in-place
reconfiguration. Retain the original config for safe `down`; create another
deployment using a separate `--config` and new `--remote-dir`, checking free
ports and approvals. Old data is retained, but database history is not
automatically migrated into the new workspace.

## 4. Check and start

```bash
python3 durka.py traffic live doctor --bundle local/packmate-live-images
python3 durka.py traffic live up --bundle local/packmate-live-images \
  --apply --host-network-approved --interface-scope-approved
```

The second command **changes the source**: loads transferred images if needed,
creates only a new private workspace and two owned containers. No target Internet
is used: no pull/build/install; startup always uses `--no-build --pull never`.
Omit `--bundle` if the pinned images are already cached on the source. Changed or
unverified images are refused.

Expect `status: PASS`, `authenticated_capture_started: true` and the UI URL.
Authenticated readiness is checked through a temporary SSH tunnel, requiring
permitted SSH forwarding. **Traffic correctness is still unverified.** Engine and
interface identity are rechecked; an old workspace is not overwritten.

## 5. Login and inspect a transaction

On Mac, copy the password without printing it:

```bash
python3 durka.py traffic live password
```

Username is `operator`; paste the password into the UI at the URL returned by `up`.
Only the Mac clipboard changes. On other operating systems use the private
`credentials.password` field without screen broadcasting. Register services/patterns
in the UI [using the step-by-step guide](packmate.md#ui-services-and-patterns), find known **request and response**, check direction/time/repetition and
application health. A running container is not sufficient evidence.

## 6. Stop and start again

```bash
python3 durka.py traffic live status
python3 durka.py traffic live down --apply
python3 durka.py traffic live up --bundle local/packmate-live-images \
  --apply --host-network-approved --interface-scope-approved
```

Down stops only this configuration's project and retains PostgreSQL/settings.
No `down -v`, prune or directory deletion. Ownership checks prevent foreign-project
shutdown. Deployments created by older helpers are not automatically adopted.

## Troubleshooting

- SSH failed: verify ordinary SSH, fingerprint and `ssh-add`. Do not copy the key
  to the Vulnbox. The program does not use interactive password prompts.
- Ports occupied: choose free ports at init or manually stop **only a known owned**
  older deployment. Firewall is not automatically changed.
- Missing/wrong-platform images: prepare the Linux amd64 bundle.
- Engine/interface changed: review the source and permitted scope; do not guess
  replacement identifiers to bypass checks.
- Readiness timeout: owned containers may already be running. Use `status`, then
  `down --apply` if necessary; data remains.
- Incomplete transfer: the directory remains for inspection, with no automatic
  deletion/overwrite. Inspect partial resources before selecting another workspace.
  No automatic reinstall.
- No Docker/Compose or approval: this LIVE path is BLOCKED. FILE requires an
  authorized closed PCAP and does not provide continuous capture.

The Python-free target path makes no target Python calls. Linux success does not
validate Docker Desktop LIVE, the event network, sustained load or a hard disk
quota. A known transaction remains a mandatory manual acceptance step.

[LIVE/FILE selection](traffic-capture.md) · [Packmate](packmate.md)
