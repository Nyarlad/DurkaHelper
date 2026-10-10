# Defender quick sheet

English | [Русский](defense-cheatsheet-RU.md)

Before a change, know the authorized service, startup/data paths, checker and rollback owner. Keep the previous code/image and a suitable backup. No service card or manually copied hashes are required.

| Situation | Action |
|---|---|
| First access | Normal user journey, old-data sample, inventory/baseline, source scan |
| Scanner signal | Open the exact catalog link; trace input → validation → sink |
| Suspicious request | Compare normal traffic and small timestamp window; do not publish raw evidence |
| Proposed patch | One failing regression, minimal change, own/other/anonymous and old-data checks |
| Deployment | One owner, exact owned service, retained previous image/code and current data |
| Availability regression | Preserve cause; apply rehearsed code rollback, not an old DB over new rounds |
| Missing traffic | Verify authorized capture point; same LAN does not imply packet visibility |
| Unclear result | Partial/blocked, never false-clean |

[Scanner](offline-scanner.md) · [Language recipes](vulnerabilities/README.md) · [Patch checklist](patch-validation.md) · [Game day](game-day.md) · [Admin quick sheet](TEAM_LAN_ADMIN_CHEATSHEET.md)

Never use broad prune, down -v, unreviewed credential rotation, blanket firewall changes or arbitrary source execution as a shortcut. Approved state changes need a rollback. Competition checkers outrank a convenient green /health endpoint.
