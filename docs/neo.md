# Neo: distribute and run team scripts

English | [Русский](neo-RU.md)

Neo saves team scripts on a coordinator and distributes executions across connected workers and the farm's team list. Workers send matching flags to S4DFarm. It is useful when one laptop should not run every script for every target. It does not deploy defensive patches.

## Administrator

`python3 durka.py up` starts the coordinator. `python3 durka.py worker` starts the bundled light worker. Give participants the LAN coordinator address from `status` and the private `credentials.neo_key`.

Workers need the coordinator, farm and permitted targets reachable from their environment. The light image includes a shell; Python/Sage or other dependencies need separately prepared compatible workers. Start the farm before Neo.

Configure an actual Ethernet bind before sharing with native clients/workers. A loopback demo uses the in-stack worker and an internal farm URL; outside workers cannot use that container-only address.

## Install a client

Use the [v2.4.2 release](https://github.com/C4T-BuT-S4D/neo/releases/tag/v2.4.2), matching the maintained client/worker version:

| Machine | Asset |
|---|---|
| Apple Silicon Mac | `neo_client_2.4.2_darwin_arm64.zip` |
| Intel Mac | `neo_client_2.4.2_darwin_amd64.zip` |
| Linux amd64 | `neo_client_2.4.2_linux_amd64.tar.gz` |
| Linux arm64 | `neo_client_2.4.2_linux_arm64.tar.gz` |

Download/extract before leaving for the event. The archive contains `neo`, `client_config.yml` and an `exploits` directory. Run the commands below from that extracted directory. Windows has no native client in this release; use a permitted Linux environment/worker.

Edit `client_config.yml`:

```yaml
host: "<ADMIN_ETHERNET_IPV4>:5005"
grpc_auth_key: "<PRIVATE_NEO_KEY_FROM_ADMIN>"
exploit_dir: "exploits"
```

Replace the placeholders; keep the config private. Follow the normal application approval procedure on macOS if prompted. Never put the key in a screenshot or shell argument.

```bash
./neo --verbose=false --config client_config.yml --help
```

## First harmless task

Create `exploits/ready.sh` in your editor with:

```sh
#!/bin/sh
# flush=True: printf writes immediately; this task makes no target request.
printf 'worker ready for %s\n' "$1"
```

Make it executable and run locally:

```bash
chmod u+x exploits/ready.sh
./exploits/ready.sh 192.0.2.1
```

Register it **disabled** so it does not start recurring work:

```bash
./neo --verbose=false --config client_config.yml add \
  --id ready --disabled --interval 1h --timeout 3s exploits/ready.sh
```

Ask the admin to start the worker, then request one run:

```bash
./neo --verbose=false --config client_config.yml single ready
./neo --verbose=false --config client_config.yml tail --count 20 ready
```

`single` runs once on **all configured teams**. This example only prints readiness and does not contact them. Its output is not a flag and should not produce accepted flags in the farm. Look for the ready message; recurring execution remains disabled.

## Real scripts and recurring execution

Scripts receive the target IP as their first argument. Use an available interpreter/shebang and flush stdout; flags matching the configured format go to the farm. Test locally first. Never load untrusted scripts into workers.

Register your script with an explicit ID, interval and timeout using the same disabled-first `add` command. After a permitted single run succeeds, enable or disable that exact ID:

```bash
./neo --verbose=false --config client_config.yml enable <TASK_ID>
./neo --verbose=false --config client_config.yml disable <TASK_ID>
```

Adding an existing ID prompts before replacing its version. Check actual worker dependencies, scope and competition rules before enabling recurring execution. The maintained [upstream commands](https://github.com/C4T-BuT-S4D/neo/tree/2f2a4eb63f9715155844284f253ba786d330c9ae/cmd/client) define the CLI.

To contribute your own compatible native worker:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1
```

This runs in the foreground; stop it with Ctrl+C. Prepare dependencies in that environment first. Native Mac/runtime behavior still needs a rehearsal on the actual machine.

## Team workflow: clients, coordinator and workers

The same `neo` binary has two roles: commands such as `add`, `single`, `enable`, `disable` and `tail` are a control client; `run` turns that process into an execution worker. The coordinator stores scripts/configuration and assigns targets to workers. It does not execute scripts itself.

```text
Author A's client ──┐
Author B's client ──┼──> coordinator ──> connected worker(s) ──> script stdout
Admin's client ────┘                         │
                                            └──> S4DFarm queue ──> jury
```

Workers extract values matching the configured flag format from stdout and send them directly to the farm. The coordinator supplies the farm URL/authentication and team configuration. Reaching the coordinator alone is therefore insufficient: the executing worker must also reach the farm. Farm ingestion and farm-to-jury submission are separate operations; `QUEUED` is not `ACCEPTED`.

1. **Admin:** start the existing stack with `python3 durka.py up` from the DurkaHelper checkout. Share the coordinator address/key privately. Start one prepared worker: either the bundled `python3 durka.py worker`, or native `./neo ... run` below. Do not start both merely to manage tasks. The light Docker worker does not supply arbitrary script dependencies.
2. **Each author:** use a private client config pointing to that same coordinator. Use distinct task IDs, for example `ready-author-a` and `ready-author-b`; task IDs are shared, not private per participant. Set a distinct `client_id` for each worker. The shared key is trusted-team access, not a read-only participant role.
3. **Register:** upload a script disabled. Wait until the worker has downloaded it and its execution loops have restarted before requesting a single run. Dependencies and auxiliary files must exist in the worker's environment, not merely on the uploading laptop.
4. **Observe:** inspect task output and then the farm entry/status. Closing an author's control client does not stop an enabled task while the coordinator and worker remain running. Disable that exact task explicitly.
5. **Submission:** the admin separately enables the farm's approved receiver. Confirm the receiver's accepted response; a printed value or queue entry alone does not prove acceptance.

### One-shot and scheduled harmless example

Use the `ready.sh` from [First harmless task](#first-harmless-task). Run these commands from the extracted Neo client directory on either the admin's machine or a participant's machine, with that machine's private `client_config.yml`. They modify shared task state, so use your own agreed ID.

```bash
./neo --verbose=false --config client_config.yml add \
  --id ready-author-a --disabled --interval 1m --timeout 3s exploits/ready.sh
```

The administrator starts a compatible worker in a **separate terminal**, from its own extracted client directory:

```bash
./neo --verbose=false --config client_config.yml run --jobs 1 --endless-jobs 0
```

After its download/loop-ready messages, the author or admin requests one run:

```bash
./neo --verbose=false --config client_config.yml single ready-author-a
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
```

Expect `worker ready for ...`; this is not a flag. `single` covers the configured team list and does not enable recurrence. To test scheduling deliberately:

```bash
./neo --verbose=false --config client_config.yml enable ready-author-a
# Observe subsequent runs; the configured interval is one minute.
./neo --verbose=false --config client_config.yml tail --count 20 ready-author-a
./neo --verbose=false --config client_config.yml disable ready-author-a
```

No cron job is needed. The interval belongs to the registered task, not to the author's terminal. A native worker stops with Ctrl+C; a disabled task stops future scheduled runs, but already running work may finish. To execute on the coordinator's physical machine, run a worker there as a separate process: the server alone is not an executor.

## Troubleshooting

| Symptom | Check |
|---|---|
| Cannot authenticate | Exact coordinator LAN address/port and shared key |
| Job remains waiting | A worker is running and has not exhausted its job slots |
| Newly added task is not found | Wait for its worker download and execution-loop restart, then retry one run |
| Script/interpreter failure | Shebang, executable file and dependencies on the executing worker |
| Results exist but flags do not arrive | Correct flag format and worker-to-farm route/authentication |
| Farm rejects/expires flags | Receiver adapter, token, tick/lifetime and current team map |

Raw `info` and debug output can include the farm password. Use `--verbose=false` and keep diagnostics off broadcasts/public reports. Script logs can also contain sensitive data.

[Participant guide](participant-guide.md) · [Farm](s4dfarm.md) · [Admin setup](MACOS_FULL_DEPLOYMENT_AND_TESTING.md)
