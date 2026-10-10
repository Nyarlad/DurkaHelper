# Competition scope and rules

English | [Русский](competition-rules-RU.md)

DurkaHelper contains no tournament-specific settings. Confirm current organizer rules and official clarifications before use; permission at one event does not transfer to another.

| Area | Confirm before applying |
|---|---|
| Prepared material | Local scripts, source copies and repository access |
| AI / external APIs | Preparation versus competition-time restrictions; the scanner calls no AI |
| Service changes | Code, configuration, dependencies, restart and migration permissions |
| Network policy | Allowed ports, filtering, proxies and container-network changes |
| Reserved infrastructure | Organizer accounts, checkers, monitoring and protected directories |
| Placement | Permitted local hosts/containers and allowed request sources |
| Traffic/data | Capture permission, observation point, storage/transfer and resource bounds |
| Communication | Team channels, outside help and publication |
| Submission protocol | Endpoint/transport, authentication, flag format, responses, quotas, tick/lifetime |
| Availability | Checker semantics, SLA, legacy-data retention and patch windows |

A hardening recipe is not permission to alter someone else's infrastructure. If a setting is protected, fix within the authorized application boundary while preserving functionality; clarify uncertain changes before applying them.

The documented competition topology uses wired LAN without VPN. Do not assume permission to change addressing, switch configuration, firewall or capture settings. The offline scanner makes no requests; health probes and infrastructure tools have explicitly different effects.
