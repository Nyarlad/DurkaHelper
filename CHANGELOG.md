# Changelog

English | [Русский](CHANGELOG-RU.md)

## Unreleased

- Ordered bilingual administrator workflows for deployment, manual patching, Neo execution, Farm submission and Packmate LIVE/FILE; consistent config selection and actual FILE UI controls.
- SSH-operated Linux LIVE deployment with read-only doctor and a separate offline AMD64 image bundle; no target Python requirement.
- Clean event state from verified cached dependencies without downloads/builds; private attachments are excluded from source publication and core archives. Release-candidate readiness and verified public access are separate gates.

- One entry point, `durka.py`, and one private config for setup, startup, status, shutdown, scanning and closed-PCAP import.
- Admin and participant guides explain how S4DFarm, Neo, Packmate and Defense tools work together.
- Offline core archives exclude runtime data and private operator configuration.
- Scanner 1.8.0: 174 offline review rules, infrastructure context and comparable reports.
- Expanded Flask config/routes/logging, Psycopg composition, PostgreSQL grants and JS driver/CORS/session boundaries; 156 additional independent fixtures. Patches remain manual.
- Defense operations 2.2.0: baseline/drift, health checks, staging recovery and deployment-policy audit.
- Pinned deployment, native backup/recovery helpers and separate Linux LIVE capture support.
- English documentation and adjacent Russian translations; 294 remediation sections.

## Release policy

See [versioning](docs/development.md#versioning). Core CI checks the native tools, not Docker Desktop, a particular laptop or the event network.
