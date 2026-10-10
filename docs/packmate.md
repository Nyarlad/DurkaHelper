# Packmate: inspect traffic

English | [Русский](packmate-RU.md)

Packmate displays requests/responses and searches stream contents. It helps defenders recognize attacks and check whether a patch changed the relevant behavior. DurkaHelper supplies its configuration and launch/import tools; upstream source remains unchanged.

## UI services and patterns

The web-interface port is chosen during deployment (`--ui-port` for SSH LIVE).
It is **not the monitored application's port**. The capture interface and
service-side IP belong in the private deployment configuration, not the service
creation form. The gear at the top right opens additional UI settings.

1. Click **+** in the top navigation bar and enter the application's **Name**
   and **Port**. Create an entry for each port. Unregistered services do not
   have their streams saved. Ordinary HTTP does not need TLS decryption.
2. Select the service in the top bar. LIVE streams appear automatically; the
   analysis-start button is only available in FILE mode.
3. For highlighting, open **Patterns → +**. Choose recognizable synthetic text,
   such as `DEMO-`, substring search, both directions and **Highlight**, not
   **Ignore**. Select a particular service if needed.
4. Open a new stream and verify its request and response. New patterns apply
   to subsequent streams; **Lookback** applies them to saved streams.
   **Pause** pauses your browser's display, not packet capture.

These actions change Packmate's database settings, not the application or
network. For an empty UI, first check the registered port and clear any pattern
filter; then check the service-side IP and availability of authorized traffic.
The controls were reviewed against the [pinned upstream UI guide](https://gitlab.com/packmate/Packmate/-/blob/938031f1dedfbedabef5b049368ed5b6ba6a900a/docs/USAGE_EN.md).

## FILE on the laptop

```bash
python3 durka.py up
python3 durka.py traffic import /path/to/closed-capture.pcap
python3 durka.py status
```

Open the printed Packmate URL. Use `credentials.packmate_user / packmate_password` from the admin's private config.

1. [Register the service and a search pattern in the UI](#ui-services-and-patterns).
2. Check `profile.packmate.local_ip`: it is the service-side IP **in the capture**, not the laptop's address.
3. Press the yellow downward-arrow FILE-processing button in the sidebar once
   and find a known request and response in the correct direction. Do not look
   for a literal "Start" label or an upload form: the import command already supplied the file.
4. For a new closed file, run the import command again; it restarts only Packmate and preserves its database/previous file.

EOF does not reset upstream's started state. Do not replace the active file manually underneath a running parser. Imported traffic can contain passwords, cookies and flags; keep it out of public artifacts.

Import does not change `local_ip`: it must match the actual service-side IP in
this PCAP, not an address copied from another demo. To change a FILE config after
setup, follow [down → edit → configure → up](MACOS_FIRST_RUN.md#6-failures-and-safe-shutdown),
then repeat the import and press the FILE-processing button.

## LIVE on Linux

LIVE needs permission and an observation point that actually sees the Vulnbox's packets: the Vulnbox itself or an approved Linux mirror/capture node. Docker Desktop's normal deployment is FILE-only.

Choose and rehearse a [capture path](traffic-capture.md) before the game. An endless FILE pipe is not LIVE: incomplete-flow timeout/periodic cleanup are tied to upstream LIVE mode. A laptop on the same switch does not see all traffic automatically.

## Resources and troubleshooting

The current Packmate image is amd64-only; Apple Silicon uses emulation. Watch CPU, memory, database/capture growth and free disk. LIVE age cleanup is not a hard disk quota; FILE has no periodic LIVE cleanup.

Empty UI: verify service registration, pattern, service-side IP, time range and a known capture. TCP/UDP direction and payload are better checks than a running container.

The maintained configuration suppresses upstream's specific authentication-failure logger that otherwise prints attempted passwords. Use the generated config; do not run stock upstream logging with private credentials.

[Traffic workflow](traffic-capture.md) · [Participant guide](participant-guide.md) · [Upstream setup](https://gitlab.com/packmate/Packmate/-/blob/938031f1dedfbedabef5b049368ed5b6ba6a900a/docs/SETUP.md)
