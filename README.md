# DurkaHelper

English | [Русский](README-RU.md)

Offline Defense Toolkit for Attack/Defense CTF: review source, investigate traffic, verify patches and run the team's shared tools from one repository.

## What does what

| Tool | Use it for |
|---|---|
| **DurkaHelper scanner** | Find suspicious code/configuration in a **local source copy** and open a fix guide. It does not scan remote hosts or apply patches. |
| **Packmate** | Read requests/responses and search traffic. Closed PCAP files on Docker Desktop; LIVE capture on an approved Linux observation point. |
| **S4DFarm** | Collect flags, track their status and submit them to the competition. |
| **Neo** | Distribute team scripts across workers and targets; send discovered flags to S4DFarm. |

Protected services stay on the Vulnbox. Apply reviewed patches there through your normal service deployment procedure. The farm handles flags, not patch distribution.

## Quick start

For source review, only Python 3.10+ is needed; no pip installation:

```bash
git clone https://github.com/Nyarlad/DurkaHelper.git
cd DurkaHelper
python3 durka.py scan /path/to/service --patches
```

Exit 1 means findings to review. Start with one service and the [fix catalog](docs/vulnerabilities/README.md). A finding is a review signal, not proof of a vulnerability.

To host the shared tools, start Docker Desktop on macOS or Docker Engine with Compose on Linux:

```bash
python3 durka.py init
```

Edit `local/durka.json`: your LAN bind address, team/service addresses, flag format and competition submission settings. Passwords and the Neo key are generated for you. Keep this file private; `local/` is ignored by Git.

Use an actual Ethernet IPv4 for teammate access and native Neo workers. Loopback is suitable for a laptop-only demo with the bundled worker.

```bash
python3 durka.py setup
python3 durka.py up
python3 durka.py status
```

`setup` downloads pinned sources/images and builds the stack; do it before going offline. `up` starts the farm, Neo coordinator and Packmate. Enable script execution and flag submission separately when ready:

```bash
python3 durka.py worker
python3 durka.py submit
```

Read the [administrator setup](docs/MACOS_FULL_DEPLOYMENT_AND_TESTING.md) before submission. The maintained farm adapter is `ructf_http`; another protocol needs a compatible adapter. Packmate uses amd64 emulation on Apple Silicon: rehearse on the actual laptop.

## During the game

1. Admin starts the tools and shares LAN URLs and credentials.
2. Defenders copy service source, scan it and investigate suspicious traffic.
3. Apply a small patch to the Vulnbox, check the service/checker and repeat the scan.
4. Script writers test their work, submit it to Neo and watch flags in S4DFarm.
5. Admin watches availability, disk and backups. Finish with `python3 durka.py down`.

Main routes: [administrator workflows 01–05](docs/ADMIN_WORKFLOWS.md), [participant guide](docs/participant-guide.md), [printable admin cheat sheet](docs/TEAM_LAN_ADMIN_CHEATSHEET.md). References: [documentation index](docs/README.md).

## Find, fix and verify

**294 sections, 174 scanner rules.** Counts describe review recipes and signals, not distinct verified exploits.

| Language / layer | Sections |
|---|---:|
| [Python](docs/vulnerabilities/python.md) | 40 |
| [JavaScript / TypeScript](docs/vulnerabilities/javascript.md) | 28 |
| [PHP](docs/vulnerabilities/php.md) | 23 |
| [Go](docs/vulnerabilities/go.md) | 19 |
| [Java](docs/vulnerabilities/java.md) | 18 |
| [C# / .NET](docs/vulnerabilities/csharp.md) | 20 |
| [C / C++](docs/vulnerabilities/c-cpp.md) | 28 |
| [Ruby / Rails](docs/vulnerabilities/ruby.md) | 18 |
| [Rust](docs/vulnerabilities/rust.md) | 18 |
| [SQL / databases](docs/vulnerabilities/sql.md) | 18 |
| [Configuration / trust boundaries](docs/vulnerabilities/configuration.md) | 64 |

## Development

Tests and synthetic fixtures are for contributors; participants need not run the full suite before each game action.

```bash
python3 -m unittest discover -s tests
python3 scripts/scanner_coverage.py --check
```

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Capabilities](docs/CAPABILITY_INVENTORY.md)

Use authorized systems and keep credentials, source, flags and captures private. DurkaHelper is [MIT licensed](LICENSE); external tools keep their [own licenses](THIRD_PARTY_NOTICES.md).
