# How the team's tools connect

English | [Русский](team-setup-RU.md)

One administrator hosts the shared stack. Teammates open its LAN UIs and connect Neo clients. Protected services remain on the Vulnbox.

```text
Teammates ──Ethernet──> Farm UI/API ──> competition flag receiver
         ├───────────> Neo coordinator ──> workers ──> permitted targets
         └───────────> Packmate UI
Vulnbox traffic ──> approved Linux LIVE, or closed PCAP ──> Packmate FILE
Service source copy ──> DurkaHelper scan ──> reviewed patch ──> Vulnbox
```

## Who owns what

The admin owns shared configuration, startup, credentials, submission and backups. Defenders own review, patches and service regression tests. Script authors own their scripts/dependencies and confirm results in the farm. Neo workers execute trusted team code.

The farm submits **flags**; Neo distributes **scripts**. Neither automatically deploys service patches. Use the team's existing Vulnbox access/deployment procedure.

An author uploads to the shared Neo coordinator; a prepared worker executes the script and sends matching stdout results directly to the farm. Authors can share one worker and need not run one each. See the [client/worker workflow and one-shot/scheduled examples](neo.md#team-workflow-clients-coordinator-and-workers). The farm's submission process is enabled separately; queue ingestion is not jury acceptance.

## Addresses

Use the admin's Ethernet IPv4 and the ports printed by `python3 durka.py status`. Defaults: farm 8080, Neo 5005, Packmate 65000. Teammates do not use `localhost`, Docker service names or `host.docker.internal`.

Database, Redis and Docker endpoints stay private. Neo clients/workers need access to both coordinator and farm; workers additionally need allowed routes to targets. Use only ports and access permitted by the event.

## First check

At home, test the admin machine and a separate PC. At the venue, have each teammate log in, perform a useful action and reconnect. A connected Ethernet link or open TCP port alone is not enough.

The laptop does not automatically see all traffic on a switched LAN. Choose [approved LIVE or PCAP import](traffic-capture.md).

[Administrator setup](MACOS_FULL_DEPLOYMENT_AND_TESTING.md) · [Admin cheat sheet](TEAM_LAN_ADMIN_CHEATSHEET.md) · [Participant guide](participant-guide.md)
