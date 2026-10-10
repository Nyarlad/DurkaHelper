# Documentation

English | [Русский](README-RU.md)

Start with your role. English pages have a Russian translation alongside; both are available offline.

## Main routes

| You are… | Read this |
|---|---|
| Hosting shared tools | [Ordered workflows 01–05](ADMIN_WORKFLOWS.md) → [printable admin cheat sheet](TEAM_LAN_ADMIN_CHEATSHEET.md); [first Mac run](MACOS_FIRST_RUN.md) for installation |
| Defending a service or writing scripts | [Participant guide](participant-guide.md) → [defense cheat sheet](defense-cheatsheet.md) |
| Investigating traffic | [Capture/import workflow](traffic-capture.md) → [Packmate](packmate.md) |
| Deploying Linux LIVE from a laptop | [SSH doctor, offline images and startup](packmate-remote.md) |
| Reviewing a finding | [Scanner reference](offline-scanner.md) → [fix catalog](vulnerabilities/README.md) |

## How the stack fits together

[Team topology](team-setup.md) explains the connections. [S4DFarm](s4dfarm.md) collects/submits flags; [Neo](neo.md) distributes scripts; [Packmate](packmate.md) lets defenders inspect traffic. Vulnbox patches use your normal service deployment workflow.

The ordinary entrypoint is `python3 durka.py`. Configuration belongs in ignored `local/durka.json`; this route has no mandatory evidence forms or manually copied checksums.

## References

| Subject | Pages |
|---|---|
| Defense | [Workflow](defense.md), [source review](code-review.md), [patch verification](patch-validation.md), [game day](game-day.md) |
| Deployment | [Kit reference](../deployment/README.md), [offline preparation](offline-bundles.md), [local utilities](local-tools.md) |
| Development | [Contributor guide](../CONTRIBUTING.md), [rule development](development.md), [synthetic lab](../lab/README.md), [integration fixtures](../integration/README.md), [release checklist](release-checklist.md) |
| Project | [Current capabilities](CAPABILITY_INVENTORY.md), [competition rules](competition-rules.md), [licenses](../THIRD_PARTY_NOTICES.md) |

Advanced scripts retain previews and explicit parameters for filesystem/restore operations. Read their references when needed; they are not extra setup steps for every participant.
