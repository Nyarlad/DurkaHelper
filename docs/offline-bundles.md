# Offline operation

English | [Русский](offline-bundles-RU.md)

## Prepare the machine once

The scanner needs Python 3.10+; the full stack also needs Docker and cached images. Install these while connected. Follow the [Mac setup](MACOS_FULL_DEPLOYMENT_AND_TESTING.md), finish `durka.py setup`, start the stack, and test it before leaving for the event.

Keep your repository, private `local/` directory and Docker data. Do not delete Docker images, reset Docker Desktop or run cleanup/prune before an offline start. Setup can download/build; normal startup uses prepared image identities and must not silently pull.

## Rehearse without Internet

### Prepare clean event state after a rehearsal

Do not delete the prepared workspace before creating its replacement. First stop the native Neo worker (`Ctrl+C`) and run `down` with the rehearsal config. Keep the pinned source cache and Docker images. On that same prepared Mac/Linux machine:

```bash
python3 durka.py --config local/event.json prepare-clean --from-config local/rehearsal.json
python3 durka.py --config local/event.json prepare-clean --from-config local/rehearsal.json --apply
```

The first command is a read-only preview. The second writes a **new** private config and `local/event-workspace`, using verified existing image identities and local pinned source checkouts. It does not download, build, start containers, copy old databases/tasks/captures, or delete the rehearsal. It generates fresh local passwords, placeholder jury/team settings, empty persistent state and an empty FILE capture. The previous local ports are retained; the new bind is initially `127.0.0.1`. Missing images, dirty/missing source cache, a running source deployment, remote Docker endpoints or existing output paths block preparation. A failed partial candidate is retained for inspection; choose a new config filename before retrying.

Fill `local/event.json` with the actual LAN bind, team map, Vulnbox IP, flag format and approved ForcAD submission settings. Then run `configure`, `up` and `doctor` with `--config local/event.json`. Worker execution and submission remain opt-in; do not enable them with placeholder settings. The new native Neo config is `local/event-workspace/config/neo-native.yml`; use the prepared native binary, not the previous rehearsal client config. After changing the LAN bind, pass Neo's `--host MAC_LAN_IP:NEO_PORT` override to the new config. Prepare each script's dependencies separately.

Verify the new installation and disconnected startup before removing the old rehearsal config/workspace. Retain the repository, pinned source cache, cached images, Neo binary and separate Linux LIVE image bundle. Re-create the LIVE target config for the actual authorized host/interface; its populated rehearsal config is not portable. This prepares **fresh application state on an already prepared machine**, not an offline installer for a blank Mac. Do not use Docker prune/reset or broad deletion of `local/`.

Keep Ethernet/LAN access, but disconnect the Internet using your own permitted arrangement. Do not change event networking.

```bash
python3 durka.py down
python3 durka.py up
python3 durka.py status
```

Open Farm and Packmate, test Neo with a harmless script, scan a local service copy and import a closed synthetic PCAP. Stop and start again. If anything attempts a download, fix the preparation while still at home. Manual PCAP analysis remains available when LIVE capture is not permitted.

This is an offline restart on a prepared machine, not installation on an empty machine. Exporting Docker images alone does not include Python, Docker Desktop, local config, licenses or Neo client binaries.

## Optional core archive

Maintainers can create a tracked-only source archive from a committed checkout. The output parent must exist and the archive path must be new.

```bash
python3 scripts/build_offline_bundle.py --output ../offline-kit/durkahelper-core.tar.gz
python3 scripts/build_offline_bundle.py --verify ../offline-kit/durkahelper-core.tar.gz
```

The core archive excludes keys, local data, logs and PCAP. It does not contain third-party runtimes/images. Verification is automatic; no hash needs to be transcribed for ordinary operation.

## Moving an external cache

For transport to another machine, advanced export/import utilities preserve pinned image identities and verify the incoming inventory. They are not part of routine startup.

```bash
python3 scripts/toolchain_inventory.py --help
python3 scripts/toolchain_bundle.py --help
```

These lower-level commands deliberately require an independently trusted input for imported archives. Do not bypass that check or treat a partial image export as a complete installation kit. Keep populated inventories private. Review [third-party licenses](../THIRD_PARTY_NOTICES.md) before redistribution; the [developer fixtures](../integration/README.md) exercise isolated cold-start behavior.
