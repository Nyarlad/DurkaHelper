# Participant guide

English | [Русский](participant-guide-RU.md)

You do not need to install the farm or fill the administrator's config. Ask the admin for the farm/Packmate LAN URLs and logins; script writers also need the Neo coordinator address/key.

## Defend a service

1. Obtain an authorized local source copy of your Vulnbox service.
2. From the DurkaHelper checkout, scan it:

```bash
python3 durka.py scan /path/to/service --patches
```

3. Open the linked [fix recipe](vulnerabilities/README.md), check whether the signal applies and inspect the relevant request/response in Packmate.
4. Save the original files/native database backup needed by that service. Apply one small fix through the team's normal Vulnbox access/deployment procedure.
5. Check legitimate use and the competition checker, including restart/data persistence where relevant. Repeat the source scan.

The scanner is offline source review: it neither probes remote Vulnboxes nor executes their code. Exit 1 means findings; exit 2 means invalid/partial input needing attention. A clean report does not replace an availability check or manual authorization/business-logic review.

## Inspect traffic

Open Packmate's LAN URL and log in. Select your service, search a suspicious value/path and examine both request and response. Ask the admin to register the service/pattern before FILE processing.

If traffic is missing, check stream timestamps, service-side IP and port/pattern and whether the admin has imported a closed file or chosen a permitted LIVE source. Do not assume a time-filter UI exists. A Mac connected to Ethernet does not capture the whole LAN automatically. [Traffic guide](traffic-capture.md).

## Write and distribute scripts

Neo is the script runner/distributor. The farm collects the resulting flags. Start with a local test against an allowed target and make dependencies explicit.

The script receives the target IP as its first command-line argument; print flags to stdout without buffering. Keep diagnostics distinct from flags. Include a shebang for the interpreter available on each worker. The bundled light worker has a shell, not Python/Sage and arbitrary packages.

Follow [Neo setup and first task](neo.md) to configure a compatible client. Register a trusted script disabled first, then request a single run before enabling recurring execution. Neo's `single` runs once on **all configured teams**, so check the team map/scope with the admin.

Watch execution output and the flags/status in the farm. Do not use the farm/Neo as an automatic defensive patch installer.

## If access fails

Use the admin's LAN address, not `localhost`. If only your device fails, compare URL/port, credentials and Neo version. If everyone fails, ask the admin to check `python3 durka.py status` and the LAN bind.

Keep private source, credentials, flags and traffic out of shared screen broadcasts. [Defender cheat sheet](defense-cheatsheet.md) · [Tool connections](team-setup.md).
