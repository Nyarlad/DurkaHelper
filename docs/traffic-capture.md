# Traffic: LIVE or PCAP import

English | [Русский](traffic-capture-RU.md)

Prepare both routes before the event. Choose the one the organizers permit; no code changes are needed for normal FILE import.

## Choose a route

| What is available | Use |
|---|---|
| You may run capture on the Vulnbox/native Linux node and see its interface traffic | Packmate LIVE on that Linux node |
| An approved Linux mirror/capture interface is provided | Packmate LIVE there; organizers provide the mirror |
| Only closed PCAP files or authorized SSH/tcpdump access | Transfer closed files and use Packmate FILE on the laptop |
| No permitted traffic source | Continue source review; traffic analysis is unavailable |

A Mac on the same Ethernet switch does not automatically see Vulnbox packets. Docker Desktop's maintained route is FILE-only. An endless FILE pipe is not a substitute for LIVE: this upstream ties incomplete-flow timeouts and periodic cleanup to LIVE.

## FILE on the laptop

Start the stack, obtain a **closed** capture and import:

```bash
python3 durka.py up
python3 durka.py traffic import /path/to/closed-capture.pcap
python3 durka.py status
```

The command checks the file internally, retains the prior capture and restarts only Packmate. Its database and other tools remain running. No manual SHA/card is needed.

In Packmate: register the service/pattern, check the service-side IP in the configuration and press the yellow downward-arrow FILE-processing button in the sidebar once. Find a known request and response. See the [UI guide](packmate.md#file-on-the-laptop) for the distinction between importing and processing. Repeat the import command and processing button for each new file. EOF does not reset the upstream parser; do not copy a new capture directly over a running FILE input.

Manual media delivery is valid too. Keep captures private: they can contain cookies, credentials and flags.

## Capture a closed file on Linux

Prefer organizer-provided files. If you have permitted capture access and existing `tcpdump`/`timeout`, run this from a private directory on the source. Replace all placeholders with the approved interface/service/ports and a **new** filename:

```bash
umask 077
timeout --signal=INT 60 tcpdump -i <APPROVED_INTERFACE> -p -nn -s 65535 \
  -c 1000 -w <NEW_PRIVATE_PREFIX>.pcap \
  'host <SERVICE_IPV4> and (tcp port <TCP_PORT> or udp port <UDP_PORT>)'
```

Wait for the process to exit before transferring. This records up to 60 seconds or 1,000 packets, approximately 66 MB plus format overhead. `timeout` exit 124 may be expected; other capture errors need checking. The recipe follows the [tcpdump manual](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in) and is a reviewed procedure, not a test of your event interface.

With an existing approved SSH identity and trusted host key:

```bash
scp -o StrictHostKeyChecking=yes -P <SSH_PORT> \
  <USER>@<SOURCE_HOST>:<EXACT_CLOSED_FILE> ./incoming-01.pcap
python3 durka.py traffic import ./incoming-01.pcap
```

Run these two commands on the laptop from the repository root. Keep the source until import/use succeeds. Never transfer a file still being written.

## Host-interface LIVE

For normal laptop-operated startup use [SSH deployment with doctor and offline images](packmate-remote.md).
No Python is required on the Vulnbox. The low-level Linux helper below remains available for advanced manual procedures.

This is the Linux administrator's branch, separate from Docker Desktop. Requirements: native Linux amd64, standard local rootful Docker Engine, cached pinned Packmate/PostgreSQL images and permission for the **entire selected interface**. The pinned upstream briefly uses a broad TCP/UDP filter during startup.

The launcher uses host networking and NET_RAW; not privileged or NET_ADMIN. It leaves the database on IPv4 loopback and does not change firewall, routes or switch configuration.

Inspect the intended Engine/interface:

```bash
docker info --format '{{.ID}}'
ip -json link show
```

Put the observed Engine ID/interface name/index/MAC and actual addresses in a private `local/packmate-host.json`:

```json
{
  "schema": "durkahelper.packmate-host.v1",
  "daemon_id": "REPLACE_ENGINE_ID",
  "interface": "eth0", "ifindex": 2, "interface_mac": "02:00:00:00:00:01",
  "local_ip": "192.0.2.10", "bind_address": "192.0.2.20",
  "ui_port": 65000, "db_port": 55432,
  "tcp_timeout_seconds": 30, "udp_timeout_seconds": 10,
  "timeout_check_seconds": 5, "retention_minutes": 60,
  "cleanup_interval_minutes": 1
}
```

These values are examples. `local_ip` means the service-side IP in the traffic; `bind_address` serves the team's UI. Use a separate private credentials JSON with `username`, `password`, `db_password`; passwords are distinct generated 20–128 character safe ASCII values. Keep these files under an owner-only directory.

On the approved Linux host, prepare a new workspace and start:

```bash
python3 deployment/packmate_host.py prepare \
  --workspace ../private-deployment/host-live-01 \
  --profile local/packmate-host.json \
  --credentials local/packmate-host-credentials.json \
  --apply --approval-id host-live-prepare
python3 deployment/packmate_host.py up \
  --workspace ../private-deployment/host-live-01 \
  --capture-approval '<INTERFACE>:<IFINDEX>:<MAC>' \
  --host-network-approved --interface-scope-approved \
  --apply --approval-id host-live-start
```

Register services/patterns in the UI and verify known TCP/UDP requests/responses, direction, delay, unfinished flows and restart. Packet visibility must come from the approved host/mirror placement. Age cleanup is not a hard disk quota: watch storage growth.

To stop only this capture deployment and retain data:

```bash
python3 deployment/packmate_host.py down \
  --workspace ../private-deployment/host-live-01 \
  --apply --approval-id host-live-stop
```

For an already approved existing container namespace, use the separate [container LIVE reference](../deployment/README.md#approved-linux-container-namespace-live). Direct helpers also support controlled cache/bootstrap operations; see their `--help` when preparing a different offline host.

## Check before relying on traffic

Find a known transaction, not just a running UI. Check both directions, timestamps, representative TCP/UDP, storage growth and restart. Stop capture if it observes the wrong scope, exposes secrets or approaches disk limits.

FILE is delayed analysis. If continuous analysis is required, a closed-file fallback alone does not satisfy that requirement. Rehearse both allowed paths and keep capture dependencies/images ready before leaving.

[Packmate](packmate.md) · [Admin cheat sheet](TEAM_LAN_ADMIN_CHEATSHEET.md)
