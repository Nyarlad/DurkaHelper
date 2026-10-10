# S4DFarm: flags and submission

English | [Русский](s4dfarm-RU.md)

S4DFarm collects flags from the team, queues them for submission and shows accepted/rejected/expired results. Neo sends discovered flags to it automatically. **It does not distribute service patches.**

## Start through DurkaHelper

```bash
python3 durka.py up
python3 durka.py status
```

Open the printed farm URL; the password is `credentials.farm_password` in private `local/durka.json`. Give teammates that LAN URL/password, not the PostgreSQL/Redis configuration.

## Configure the competition

In `local/durka.json`, set the actual team map, flag regex, submit limits/timing and `profile.farm.protocol_settings` URL/token. The kit currently supports `ructf_http`; the upstream's absent default adapter is not used.

Submission starts disabled. After checking that the receiver matches the competition:

```bash
python3 durka.py submit
```

Watch a legitimate flag's final status. A running UI, queue entry or successful Neo login does not prove submission acceptance. If queues stall, check submission enabled, adapter/token, expiry and receiver responses.

## Change configuration or recover

For event settings: stop, edit the private config, run `python3 durka.py configure`, then start. Keep old/expired recovered queues from replaying. The [native recovery procedure](../deployment/README.md#native-backup-and-quarantine-restore) restores into new storage and deliberately clears candidate Redis state.

Exact upstream versions live in the [toolchain lock](../config/toolchain.lock.json); DurkaHelper preparation handles them. [Admin setup](MACOS_FULL_DEPLOYMENT_AND_TESTING.md) · [Neo](neo.md) · [Upstream](https://github.com/C4T-BuT-S4D/S4DFarm)
