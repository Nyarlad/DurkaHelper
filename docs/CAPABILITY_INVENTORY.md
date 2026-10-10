# Capabilities and limits

English | [Русский](CAPABILITY_INVENTORY-RU.md)

Use the [main guide](MACOS_FULL_DEPLOYMENT_AND_TESTING.md) for setup and the [admin sheet](TEAM_LAN_ADMIN_CHEATSHEET.md) during operation.

| Tool | What it does | Important limit |
|---|---|---|
| DurkaHelper scanner | Reviews local source/configuration; 174 rules and a 294-section remediation guide | Findings need review; no remote exploit or automatic patching |
| Defense operations | Baseline, file drift, health, patch comparison, staged file recovery | Explicit scope; HTTP health is not a competition checker |
| S4DFarm | Receives flags and submits them to the competition | Only the existing ructf_http adapter is maintained; it does not distribute patches |
| Neo | Coordinates team scripts and workers | Enable trusted tasks deliberately; script dependencies must exist in the worker |
| Packmate FILE | Searches request/response streams from a closed PCAP | Not continuous capture; published image uses amd64 on Apple Silicon |
| Packmate LIVE | Captures at an authorized Linux observation point | A LAN-connected Mac does not automatically see Vulnbox traffic |
| Deployment helpers | Prepare pinned components, preserve data, stop only their own project | Docker runtime required; Windows supports the core, not this deployment |
| Recovery helpers | Native dumps and isolated candidate restores | No blind production overwrite or queue replay |
| Offline operation | Core without downloads; prepared deployment without pulls/builds | Install/cache the external runtime first; copying the repository alone is not enough |

## Support

The core is Python 3.10+ standard-library-only. Windows, Linux x86-64 and hosted macOS ARM64 are covered by tests; Docker-based integration is exercised on Linux x86-64. The actual Mac, Docker Desktop, traffic visibility and team devices still need a local rehearsal. CI logs live in GitHub Actions, not as reports inside this repository.

Versions and image identities are maintained in [toolchain.lock.json](../config/toolchain.lock.json). They are checked automatically: operators do not fill SHA forms.

A passing scan is not proof that a service is secure. A passing lab is not proof that the event network permits capture or that every participant can reach the tools.
