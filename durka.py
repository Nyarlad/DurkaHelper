#!/usr/bin/env python3
"""DurkaHelper operator commands: configure, prepare, start, scan and import traffic."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "local/durka.json"
SCHEMA = "durkahelper.operator.v1"
CONFIG_FILES = ("config/farm.py", "config/neo-server.yml", "config/packmate.properties", "profile.json", "compose.json", "model.json", "policy.json",
                "runtime-compose.json", "runtime-model.json", "runtime-policy.json", "build-receipt.json", "deployment.json")
CONFIG_JOURNAL = ".durka-configuration.json"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


# Operator commands must not leave import-cache writes in an offline checkout;
# this also keeps the doctor path read-only without requiring a special flag.
sys.dont_write_bytecode = True
kit = module("durka_deployment", "deployment/toolkit.py")
Error = kit.Error


def target_platform():
    architecture = {"aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine(), platform.machine())
    if sys.platform == "darwin" and architecture == "arm64":
        return {"os": "darwin", "architecture": "arm64", "runtime": "docker-desktop"}
    if sys.platform.startswith("linux") and architecture in {"amd64", "arm64"}:
        return {"os": "linux", "architecture": architecture, "runtime": "docker-engine"}
    # Windows can configure an Apple Silicon deployment and run the scanner.
    return {"os": "darwin", "architecture": "arm64", "runtime": "docker-desktop"}


def private_directory(path):
    path = kit.shared.no_links(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or (os.name != "nt" and path.stat().st_mode & 0o077):
        raise Error("operator directories must be private (chmod 700); use a new private directory")
    return path


def config_path(value):
    return kit.shared.no_links(Path(value).absolute())


def init(path):
    path = config_path(path)
    if path.exists():
        raise Error("configuration already exists; edit it instead of running init again")
    private_directory(path.parent)
    value = kit.load(ROOT / "config/durka.example.json")
    value["profile"]["platform"] = target_platform()
    value["profile"]["allow_amd64_emulation"] = value["profile"]["platform"]["architecture"] == "arm64"
    value["credentials"] = {name: secrets.token_hex(20) for name in
                            ("farm_password", "database_password", "neo_key", "packmate_password")}
    value["credentials"]["packmate_user"] = "operator"
    kit.shared.write(path, kit.shared.canonical(value))
    print("Created " + str(path))
    print("Edit the LAN address, team map and competition settings before setup. Passwords are stored in this private file.")
    if os.name == "nt":
        print("Run deployment commands on the Mac or Linux host; source scanning also works on Windows.")
    elif value["profile"]["platform"]["architecture"] == "arm64":
        print("Packmate uses its pinned amd64 image through Docker emulation on ARM64.")
    return 0


def load_config(path):
    path = config_path(path)
    try:
        value = kit.load(path)
    except FileNotFoundError as error:
        raise Error("configuration is missing; run python3 durka.py init first") from error
    if (not isinstance(value, dict) or set(value) != {"schema", "profile", "credentials", "paths"}
            or value["schema"] != SCHEMA or not isinstance(value["paths"], dict)
            or set(value["paths"]) != {"sources", "workspace"}):
        raise Error("invalid operator configuration; use config/durka.example.json as the reference")
    kit.validate_profile(value["profile"])
    kit.validate_credentials(value["credentials"])
    paths = {}
    for name, text in value["paths"].items():
        if not isinstance(text, str) or not text.strip():
            raise Error("sources and workspace paths must be nonempty")
        candidate = Path(text)
        paths[name] = kit.shared.no_links(candidate if candidate.is_absolute() else ROOT / candidate)
        if paths[name] == ROOT or paths[name] in ROOT.parents:
            raise Error("deployment paths must use dedicated directories")
    if (paths["sources"] == paths["workspace"] or paths["sources"] in paths["workspace"].parents
            or paths["workspace"] in paths["sources"].parents):
        raise Error("source and deployment directories must be separate")
    return value, paths


def args_for(action, workspace, **values):
    defaults = dict(action=action, workspace=str(workspace), apply=True,
                    approval_id="operator-" + secrets.token_hex(8), runtime=False,
                    connected_preparation=False, protocol_reviewed=False, queue_reviewed=False,
                    profile=None, credentials=None, s4dfarm_source=None, neo_source=None)
    defaults.update(values)
    return SimpleNamespace(**defaults)


def require_host(profile):
    if os.name == "nt":
        raise Error("deployment commands require macOS or Linux; use scan on Windows")
    if profile["platform"] != target_platform():
        raise Error("configured platform differs from this host; correct profile.platform before setup")


def source_checkout(root, component, source):
    """Fetch only a locked repository/commit; resume only our private source cache."""
    expected = {"schema": "durkahelper.operator-sources.v1", "sources": source}
    if root.exists():
        private_directory(root)
        if not (root / ".durka-sources.json").is_file() or kit.load(root / ".durka-sources.json") != expected:
            raise Error("source directory is not this operator cache; choose a new sources path")
    else:
        private_directory(root)
        kit.shared.write(root / ".durka-sources.json", kit.shared.canonical(expected))
    path = kit.shared.no_links(root / component)
    item = source[component]
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
                       GIT_NO_REPLACE_OBJECTS="1", GIT_ATTR_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0")

    def git(*argv, capture=False):
        return kit.shared.checked(["git", "-c", "core.hooksPath=" + os.devnull,
                                   "-c", "core.fsmonitor=false", "-C", str(path), *argv],
                                  capture=capture, timeout=600, environment=environment)

    if not path.exists():
        path.mkdir(mode=0o700)
        git("init", "--template=")
        git("remote", "add", "origin", item["repository"])
    if not (path / ".git").is_dir() or (path / ".git").is_symlink():
        raise Error("source checkout is incomplete or linked; use a new sources path")
    if git("remote", "get-url", "origin", capture=True).decode().strip() != item["repository"]:
        raise Error("source checkout origin differs from the locked upstream")
    try:
        head = git("rev-parse", "--verify", "HEAD", capture=True).decode().strip()
    except Error:
        head = None
    if head is not None:
        if head != item["commit"] or git("status", "--porcelain", "--untracked-files=all", capture=True):
            raise Error("source checkout changed; use a new sources path rather than overwriting it")
    else:
        git("fetch", "--depth", "1", "origin", item["commit"])
        git("checkout", "--detach", item["commit"])
    if git("rev-parse", "HEAD", capture=True).decode().strip() != item["commit"]:
        raise Error("source checkout did not resolve to the locked version")
    return path


def check_config(root, value):
    if not root.exists():
        raise Error("deployment is missing; run python3 durka.py setup first")
    root, state, spec, profile = kit.workspace(root)
    if profile != value["profile"] or spec != kit.compose_spec(profile, value["credentials"], state["project"],
                                                             kit.shared.image_map(ROOT / "config/integration-images.lock.json")):
        raise Error("configuration changed after setup; run durka.py down, then durka.py configure to apply event settings")
    if not credentials_match(root, state, spec, profile, value["credentials"]):
        raise Error("configuration changed after setup; keep the old workspace for its data and set paths.workspace to a new directory")
    return root, state, spec, profile


def credentials_match(root, state, spec, profile, credentials):
    return (spec == kit.compose_spec(profile, credentials, state["project"],
                                    kit.shared.image_map(ROOT / "config/integration-images.lock.json"))
            and kit.read(root / "config/packmate.properties").decode("ascii") == kit.properties(profile, credentials)
            and ('grpc_auth_key: "' + credentials["neo_key"] + '"\n') in
            kit.read(root / "config/neo-server.yml").decode("ascii"))


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def replace_file(path, data, expected):
    """Replace one known private file atomically; never blindly overwrite a changed file."""
    if checksum(kit.read(path)) != expected:
        raise Error("configuration changed concurrently; retained backup must be inspected")
    metadata = path.lstat()
    temporary = path.with_name(".durka-write-" + secrets.token_hex(8))
    try:
        kit.shared.write(temporary, data)
        temporary.chmod(metadata.st_mode & 0o777)
        if checksum(kit.read(path)) != expected:
            raise Error("configuration changed concurrently; retained backup must be inspected")
        os.replace(temporary, path)
        if kit.read(path) != data:
            raise Error("configuration changed during publication; retained backup must be inspected")
    finally:
        if temporary.exists():
            temporary.unlink()


def bind_paths(root, paths):
    expected = {"schema": "durkahelper.operator-paths.v1", "paths": {name: str(path) for name, path in paths.items()}}
    path = root / "operator-paths.json"
    if path.exists():
        if kit.load(path) != expected:
            raise Error("operator paths changed; retain the existing deployment and restore its original paths")
        return
    root, state, _, _ = kit.workspace(root)
    before = kit.read(root / "deployment.json")
    kit.shared.write(path, kit.shared.canonical(expected))
    state["files"]["operator-paths.json"] = checksum(kit.read(path))
    replace_file(root / "deployment.json", kit.shared.canonical(state), checksum(before))


def stopped(state):
    kit.owned_resources(state)
    identities = kit.shared.checked(["docker", "ps", "--all", "--quiet", "--filter",
                                     "label=com.docker.compose.project=" + state["project"]], capture=True).decode().split()
    if len(identities) > 64 or any(not re.fullmatch(r"[a-f0-9]{12,64}", item) for item in identities):
        raise Error("unexpected deployment resource inventory")
    for identity in identities:
        state_text = kit.shared.checked(["docker", "container", "inspect", "--format",
                                         "{{.State.Running}};{{.State.Restarting}}", identity], capture=True).decode().strip()
        if state_text != "false;false":
            raise Error("stop the entire deployment with durka.py down before configure")


def pending(root):
    path = root / CONFIG_JOURNAL
    if path.exists() and kit.load(path).get("phase") == "pending":
        raise Error("configuration update was interrupted; run durka.py configure --rollback")


def configuration_rollback(root):
    """Recover only the bounded files of the latest recorded configuration change."""
    journal = kit.load(root / CONFIG_JOURNAL)
    if (set(journal) != {"schema", "phase", "backup", "files"} or journal["schema"] != "durkahelper.operator-configuration.v1"
            or journal["phase"] not in {"pending", "committed", "rolled-back"}
            or not isinstance(journal["backup"], str)
            or not re.fullmatch(r"configuration-backups/[a-f0-9]{16}", journal["backup"])
            or not isinstance(journal["files"], dict) or set(journal["files"]) != set(CONFIG_FILES)):
        raise Error("invalid configuration recovery record")
    backup = kit.shared.no_links(root / journal["backup"])
    originals = {}
    for name, hashes in journal["files"].items():
        if (not isinstance(hashes, dict) or set(hashes) != {"before", "after"}
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in hashes.values())):
            raise Error("invalid configuration recovery checks")
        originals[name] = kit.read(backup / name)
        if checksum(originals[name]) != hashes["before"] or checksum(kit.read(root / name)) not in set(hashes.values()):
            raise Error("configuration recovery files changed; retained backup must be inspected")
    state = json.loads(originals["deployment.json"])
    if (state.get("schema") != kit.SCHEMA or state.get("source_pins") != kit.shared.PINS
            or not re.fullmatch(r"dh-deploy-[a-f0-9]{12}", state.get("project", ""))
            or not isinstance(state.get("files"), dict) or not 1 <= len(state["files"]) <= 20000):
        raise Error("configuration recovery ownership record is invalid")
    for name, digest in state["files"].items():
        if (not isinstance(name, str) or Path(name).is_absolute() or "\\" in name or ":" in name
                or any(part in {"..", "."} for part in name.split("/"))):
            raise Error("unsafe recovery member")
        candidate = kit.shared.no_links(root / name)
        data = originals[name] if name in originals else kit.read(candidate, kit.shared.MAX_SOURCE)
        if checksum(data) != digest:
            raise Error("original deployment changed outside configuration; refusing recovery")
    stopped(state)
    for name in CONFIG_FILES:
        current = checksum(kit.read(root / name))
        if current != journal["files"][name]["before"]:
            replace_file(root / name, originals[name], current)
    root, state, spec, _ = kit.workspace(root)
    kit.check_build_receipt(root, spec)
    before = kit.read(root / CONFIG_JOURNAL)
    journal["phase"] = "rolled-back"
    replace_file(root / CONFIG_JOURNAL, kit.shared.canonical(journal), checksum(before))
    return backup / "operator.json"


def configure(value, paths, rollback=False):
    require_host(value["profile"])
    root = paths["workspace"]
    if rollback:
        previous = configuration_rollback(root)
        print("Previous deployment configuration restored; data retained.")
        print("Copy " + str(previous) + " over the private operator config before up.")
        return 0
    pending(root)
    root, state, old_spec, old_profile = kit.workspace(root)
    expected_paths = {"schema": "durkahelper.operator-paths.v1", "paths": {name: str(path) for name, path in paths.items()}}
    if kit.load(root / "operator-paths.json") != expected_paths:
        raise Error("configure cannot change operator paths; restore the original paths")
    new_profile = value["profile"]
    if (any(old_profile[name] != new_profile[name] for name in ("schema", "platform", "allow_amd64_emulation"))
            or any(old_profile["packmate"][name] != new_profile["packmate"][name] for name in ("mode", "pcap_file", "interface"))
            or new_profile["packmate"]["mode"] != "FILE"):
        raise Error("configure changes event settings only; platform, runtime and capture layout require a new deployment")
    if not credentials_match(root, state, old_spec, old_profile, value["credentials"]):
        raise Error("configure cannot rotate credentials; restore their original values")
    old_runtime = kit.check_build_receipt(root, old_spec)
    receipt = kit.load(root / "build-receipt.json")
    stopped(state)
    kit.check_build_receipt(root, old_spec, kit.image_preflight(old_runtime, old_profile))
    spec = kit.compose_spec(new_profile, value["credentials"], state["project"],
                            kit.shared.image_map(ROOT / "config/integration-images.lock.json"))
    runtime = kit.runtime_spec(spec, receipt["images"])
    deployment_model = kit.model(spec, new_profile)
    runtime_model = kit.model(runtime, new_profile)
    farm = new_profile["farm"]
    farm_config = dict(DEBUG=False, TEAMS=farm["teams"], FLAG_FORMAT=farm["flag_format"], SYSTEM_PROTOCOL=farm["protocol"],
                       SUBMIT_FLAG_LIMIT=farm["submit_limit"], SUBMIT_PERIOD=farm["submit_period"], FLAG_LIFETIME=farm["flag_lifetime"],
                       SERVER_PASSWORD=value["credentials"]["farm_password"], TIMEZONE="UTC", **farm["protocol_settings"])
    candidate = {"config/farm.py": ("CONFIG = " + repr(farm_config) + "\n").encode("utf-8"),
                 "config/neo-server.yml": ('db_path: "/data/db.db"\nredis_url: "redis://neo-redis:6379/0"\nbase_dir: "/data/exploits"\nping_every: "5s"\nsubmit_every: "2s"\ngrpc_auth_key: "' + value["credentials"]["neo_key"] + '"\nfarm:\n  url: "' + kit.neo_farm_url(new_profile) + '"\n  password: "' + value["credentials"]["farm_password"] + '"\n').encode("ascii"),
                 "config/packmate.properties": kit.properties(new_profile, value["credentials"]).encode("ascii"),
                 "profile.json": kit.shared.canonical(new_profile), "compose.json": kit.shared.canonical(spec),
                 "model.json": kit.shared.canonical(deployment_model), "policy.json": kit.shared.canonical(kit.policy(new_profile, deployment_model)),
                 "runtime-compose.json": kit.shared.canonical(runtime), "runtime-model.json": kit.shared.canonical(runtime_model),
                 "runtime-policy.json": kit.shared.canonical(kit.policy(new_profile, runtime_model)),
                 "build-receipt.json": kit.shared.canonical({"schema": "durkahelper.deployment-build.v2", "images": receipt["images"],
                    "compose_sha256": checksum(kit.shared.canonical(spec)), "runtime_sha256": checksum(kit.shared.canonical(runtime))})}
    originals = {name: kit.read(root / name) for name in CONFIG_FILES}
    for name, payload in candidate.items():
        if name in state["files"]:
            state["files"][name] = checksum(payload)
    candidate["deployment.json"] = kit.shared.canonical(state)
    backup = root / "configuration-backups" / secrets.token_hex(8)
    private_directory(backup)
    for name, data in originals.items():
        kit.shared.write(backup / name, data)
    old_operator = dict(value, profile=old_profile)
    kit.shared.write(backup / "operator.json", kit.shared.canonical(old_operator))
    journal = {"schema": "durkahelper.operator-configuration.v1", "phase": "pending", "backup": backup.relative_to(root).as_posix(),
               "files": {name: {"before": checksum(originals[name]), "after": checksum(candidate[name])} for name in CONFIG_FILES}}
    journal_path = root / CONFIG_JOURNAL
    if journal_path.exists():
        replace_file(journal_path, kit.shared.canonical(journal), checksum(kit.read(journal_path)))
    else:
        kit.shared.write(journal_path, kit.shared.canonical(journal))
    try:
        for name in CONFIG_FILES:
            stopped(state)
            replace_file(root / name, candidate[name], checksum(originals[name]))
        kit.workspace(root)
        kit.check_build_receipt(root, spec)
        before = kit.read(journal_path)
        journal["phase"] = "committed"
        replace_file(journal_path, kit.shared.canonical(journal), checksum(before))
    except (Exception, KeyboardInterrupt):
        configuration_rollback(root)
        raise
    print("Event settings updated. Data and cached images retained; no downloads or rebuild required.")
    print("Previous configuration: " + str(backup / "operator.json"))
    print("Run python3 durka.py up, then worker and submit when needed.")
    return 0


def empty_capture(root, profile):
    path = root / "pcaps" / profile["packmate"]["pcap_file"]
    if path.is_symlink():
        raise Error("capture path cannot be a link")
    if not path.exists():
        kit.shared.write(path, struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        path.chmod(0o644)  # Read by the unprivileged Packmate container; private workspace parent.


def prepare_clean(config, from_config, apply=False):
    """Create fresh private state from verified cached images, never clone data."""
    target = config_path(config)
    source_config = config_path(from_config)
    old_value, old_paths = load_config(source_config)
    pending(old_paths["workspace"])
    old_root, old_state, old_spec, old_profile = check_config(old_paths["workspace"], old_value)
    old_runtime = kit.check_build_receipt(old_root, old_spec)
    if target == source_config or target.exists():
        raise Error("clean configuration must be a new file; existing files are retained")
    root = target.with_name(target.stem + "-workspace")
    if root.exists() or any(root == path or root in path.parents or path in root.parents for path in old_paths.values()):
        raise Error("clean workspace must be new and separate from the previous deployment and source cache")
    if not apply:
        print("Preview: new configuration and empty deployment state, reusing verified cached images.")
        print("No downloads, builds, container changes or file writes. Use --apply to prepare.")
        return 0
    require_host(old_profile)
    # Cached images must come from this machine, not a remotely selected daemon.
    endpoint = os.environ.get("DOCKER_HOST") if not os.environ.get("DOCKER_CONTEXT") else None
    if not endpoint:
        endpoint = kit.shared.checked(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], capture=True).decode().strip()
    if not endpoint.startswith("unix://") or endpoint[7:].startswith("@"):
        raise Error("clean offline preparation requires the local Docker Unix socket")
    stopped(old_state)
    identities = kit.image_preflight(old_runtime, old_profile)
    kit.check_build_receipt(old_root, old_spec, identities)
    checkouts = {name: kit.shared.no_links(old_paths["sources"] / name) for name in kit.shared.PINS}
    for name, path in checkouts.items():
        if (kit.shared.git_read(path, ["rev-parse", "HEAD"]).decode().strip() != kit.shared.PINS[name]
                or kit.shared.git_read(path, ["status", "--porcelain", "--untracked-files=all"])):
            raise Error("offline source cache must contain the clean retained source pins")
    value = kit.load(ROOT / "config/durka.example.json")
    value["profile"]["platform"] = old_profile["platform"]
    value["profile"]["allow_amd64_emulation"] = old_profile["allow_amd64_emulation"]
    value["profile"]["ports"] = old_profile["ports"]
    value["credentials"] = {name: secrets.token_hex(20) for name in old_value["credentials"]}
    value["credentials"]["packmate_user"] = "operator"
    value["paths"] = {"sources": str(old_paths["sources"]), "workspace": str(root)}
    paths = {name: Path(path) for name, path in value["paths"].items()}
    kit.validate_profile(value["profile"])
    kit.validate_credentials(value["credentials"])
    private_directory(target.parent)
    # prepare exports only pinned upstream sources and generates fresh config/data.
    # An interrupted candidate is retained for inspection, never erased/reused.
    with tempfile.TemporaryDirectory(prefix=".durka-clean-", dir=target.parent) as temporary:
        temporary = Path(temporary)
        kit.shared.write(temporary / "profile.json", kit.shared.canonical(value["profile"]))
        kit.shared.write(temporary / "credentials.json", kit.shared.canonical(value["credentials"]))
        kit.prepare(args_for("prepare", root, profile=str(temporary / "profile.json"),
                             credentials=str(temporary / "credentials.json"),
                             **{name + "_source": str(path) for name, path in checkouts.items()}))
    bind_paths(root, paths)
    _, _, spec, profile = kit.workspace(root)
    runtime = kit.runtime_spec(spec, identities)
    kit.image_preflight(runtime, profile)
    runtime_data = kit.shared.canonical(runtime)
    runtime_model = kit.model(runtime, profile)
    for name, data in (("runtime-compose.json", runtime_data),
                       ("runtime-model.json", kit.shared.canonical(runtime_model)),
                       ("runtime-policy.json", kit.shared.canonical(kit.policy(profile, runtime_model))),
                       ("build-receipt.json", kit.shared.canonical({"schema": "durkahelper.deployment-build.v2",
                            "images": identities, "compose_sha256": checksum(kit.shared.canonical(spec)),
                            "runtime_sha256": checksum(runtime_data)}))):
        kit.shared.write(root / name, data)
    empty_capture(root, profile)
    (root / "data/native-worker").mkdir(mode=0o700)
    native_config = ('host: "127.0.0.1:' + str(profile["ports"]["neo"]) + '"\n'
                     'grpc_auth_key: "' + value["credentials"]["neo_key"] + '"\n'
                     'exploit_dir: ' + json.dumps(str(root / "data/native-worker")) + '\n'
                     'client_id: "competition-native"\n')
    kit.shared.write(root / "config/neo-native.yml", native_config)
    kit.execute(args_for("preflight", root, runtime=True, apply=False))
    # Publish the new operator config only after all offline checks pass.
    kit.shared.write(target, kit.shared.canonical(value))
    print("Clean offline deployment prepared. Previous deployment retained; no containers started.")
    print("Fresh passwords, empty databases/queues/tasks and an empty FILE capture; submission and worker disabled.")
    print("Config: " + str(target))
    print("Native Neo config: " + str(root / "config/neo-native.yml"))
    print("Before the event: fill its LAN address, teams, service IP, flag format and jury settings; run configure before up.")
    return 0


def setup(value, paths):
    require_host(value["profile"])
    root = paths["workspace"]
    if root.exists():
        if not (root / "deployment.json").is_file():
            raise Error("an incomplete workspace exists; keep it for inspection and choose a new paths.workspace directory")
        check_config(root, value)
        if (root / "build-receipt.json").exists():
            bind_paths(root, paths)
            kit.execute(args_for("preflight", root, runtime=True))
            print("Setup is already complete. Run python3 durka.py up.")
            return 0
    lock = kit.load(ROOT / "config/toolchain.lock.json")
    sources = {name: lock["components"][name]["source"] for name in kit.shared.PINS}
    sources = {name: {"repository": item["repository"], "commit": item["commit"]} for name, item in sources.items()}
    if any(sources[name]["commit"] != pin for name, pin in kit.shared.PINS.items()):
        raise Error("source lock and deployment versions differ")
    print("Preparing pinned sources and Docker images. First setup needs Internet and can take several minutes.", flush=True)
    checkouts = {name: source_checkout(paths["sources"], name, sources) for name in sources}
    if not root.exists():
        private_directory(root.parent)
        with tempfile.TemporaryDirectory(prefix=".durka-config-", dir=root.parent) as temporary:
            temporary = Path(temporary)
            kit.shared.write(temporary / "profile.json", kit.shared.canonical(value["profile"]))
            kit.shared.write(temporary / "credentials.json", kit.shared.canonical(value["credentials"]))
            kit.prepare(args_for("prepare", root, profile=str(temporary / "profile.json"),
                                 credentials=str(temporary / "credentials.json"),
                                 **{name + "_source": str(path) for name, path in checkouts.items()}))
    bind_paths(root, paths)
    images = kit.shared.image_map(ROOT / "config/integration-images.lock.json")
    refs = {**images, "neo-worker": kit.LIGHT, "packmate": kit.PACKMATE, "packmate-db": kit.PACKMATE_DB}
    for name, reference in refs.items():
        architecture = "amd64" if name == "packmate" else value["profile"]["platform"]["architecture"]
        print("Preparing image: " + name, flush=True)
        kit.shared.checked(["docker", "pull", "--platform", "linux/" + architecture, reference], timeout=600)
    print("Building farm and Neo; progress is suppressed to keep credentials out of the terminal.", flush=True)
    kit.execute(args_for("build", root, connected_preparation=True))
    empty_capture(root, value["profile"])
    print("Setup complete. Run python3 durka.py up.")
    return 0


def display_urls(profile):
    for name, title in (("farm", "S4DFarm"), ("packmate", "Packmate")):
        print(title + ": http://" + profile["bind_address"] + ":" + str(profile["ports"][name]))
    print("Neo: " + profile["bind_address"] + ":" + str(profile["ports"]["neo"]) + " (task API, not a website)")


def run_operator(action, value, paths):
    require_host(value["profile"])
    if action == "down":
        # The operator normally edits their event settings before stopping.
        # Stop against the still-bound deployment, without applying those edits.
        root, _, _, _ = kit.workspace(paths["workspace"])
        kit.execute(args_for("down", root))
        print("Deployment stopped. Data and images retained.")
        return 0
    root, state, spec, profile = check_config(paths["workspace"], value)
    if action == "status":
        kit.owned_resources(state)
        built = (root / "build-receipt.json").exists()
        if built:
            kit.check_build_receipt(root, spec)
        output = kit.shared.checked(kit.command(root, state, runtime=built) +
                                    ["ps", "--all", "--format", "json"], capture=True)
        text = output.decode().strip()
        rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
        for item in rows:
            name, condition = item.get("Service", "unknown"), item.get("State", "unknown")
            if name not in spec["services"] or condition not in {"running", "exited", "created", "restarting", "paused", "dead", "removing"}:
                raise Error("Docker returned an unexpected service status")
            print(name + ": " + condition)
        if not rows:
            print("Services are stopped. Run python3 durka.py up.")
        display_urls(profile)
        print("Credentials: private credentials section in the operator config.")
        return 0
    if action == "submit":
        settings = profile["farm"]["protocol_settings"]
        host = urlsplit(settings["SYSTEM_URL"]).hostname or ""
        if host.endswith(".invalid") or settings["SYSTEM_TOKEN"].startswith("REPLACE_"):
            raise Error("set the real competition endpoint and token before enabling submission")
        kit.execute(args_for("enable-submission", root, protocol_reviewed=True, queue_reviewed=True))
        print("Farm submission queue enabled with the configured competition adapter.")
    else:
        if action == "up":
            empty_capture(root, profile)
        kit.execute(args_for(action, root))
        print({"up": "Farm, Neo server and Packmate started.", "down": "Deployment stopped. Data and images retained.",
               "worker": "Neo worker started. It runs enabled tasks from the Neo server."}[action])
        if action == "up":
            display_urls(profile)
            print("Use worker to execute Neo tasks; use submit to send farm flags. Import a closed PCAP with traffic import FILE.")
    return 0


def import_traffic(value, paths, source):
    require_host(value["profile"])
    root, state, spec, profile = check_config(paths["workspace"], value)
    if profile["packmate"]["mode"] != "FILE":
        raise Error("traffic import requires the FILE deployment profile")
    helper = module("durka_file_import", "deployment/packmate_file.py")
    try:
        _, _, summary = helper.inspect_file(source)
        daemon_id = kit.shared.checked(["docker", "info", "--format", "{{.ID}}"], capture=True).decode().strip()
        arguments = SimpleNamespace(workspace=str(root), pcap=str(source), expected_sha256=summary["sha256"],
                                    apply=True, approval_id="operator-file-" + secrets.token_hex(8), daemon_id=daemon_id,
                                    closed_pcap_confirmed=True, maintenance_confirmed=True)
        helper.replace(arguments)
    except helper.Error as error:
        raise Error(str(error)) from error
    print("Closed capture imported. Packmate database retained and the previous capture kept for recovery.")
    print("Open Packmate, select the service/patterns, then press the yellow downward-arrow FILE-processing button in the sidebar once. FILE mode processes one closed capture per session.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="private operator JSON, default: local/durka.json")
    commands = parser.add_subparsers(dest="action", required=True)
    doctor = commands.add_parser("doctor", help="read-only Mac, Docker, config and offline prerequisite checks")
    doctor.add_argument("--neo-client", help="prepared Darwin ARM64 Neo executable; default: local/neo-client/neo")
    doctor.add_argument("--json", action="store_true", help="print a sanitized machine-readable report")
    configure_parser = commands.add_parser("configure", help="apply edited event settings to a stopped deployment, without downloads")
    configure_parser.add_argument("--rollback", action="store_true", help="restore the previous deployment configuration")
    clean = commands.add_parser("prepare-clean", help="prepare empty state from a stopped deployment's cached images, without downloads/builds")
    clean.add_argument("--from-config", required=True, help="private config of the stopped prepared deployment")
    clean.add_argument("--apply", action="store_true", help="write a NEW config/workspace; previous deployment is retained")
    for name, description in (("init", "create a private config with generated passwords"),
                              ("setup", "fetch pinned dependencies and build this deployment"),
                              ("up", "start farm, Neo server and Packmate"), ("down", "stop this deployment, retaining data"),
                              ("status", "show component states and addresses"), ("worker", "start the Neo task worker"),
                              ("submit", "enable the configured competition flag-submission queue")):
        commands.add_parser(name, help=description)
    scan = commands.add_parser("scan", help="scan local source files without executing or changing them", add_help=False)
    scan.add_argument("scanner_args", nargs=argparse.REMAINDER)
    traffic = commands.add_parser("traffic", help="import a closed traffic capture into Packmate")
    traffic_commands = traffic.add_subparsers(dest="traffic_action", required=True)
    incoming = traffic_commands.add_parser("import", help="replace the current capture; the writer must already be closed")
    incoming.add_argument("file")
    remote_live = traffic_commands.add_parser("live", help="deploy Packmate LIVE by SSH, with offline images", add_help=False)
    remote_live.add_argument("live_args", nargs=argparse.REMAINDER)
    argv = list(sys.argv[1:] if argv is None else argv)
    command_index = 0
    while command_index < len(argv):
        if argv[command_index] == "--config":
            command_index += 2
        elif argv[command_index].startswith("--config="):
            command_index += 1
        else:
            break
    if argv[command_index:command_index + 2] == ["traffic", "live"]:
        args = parser.parse_args(argv[:command_index + 2])
        args.live_args = argv[command_index + 2:]
    elif command_index < len(argv) and argv[command_index] == "scan":
        args = parser.parse_args(argv[:command_index + 1])
        args.scanner_args = argv[command_index + 1:]
    else:
        args = parser.parse_args(argv)
    try:
        if args.action == "traffic" and args.traffic_action == "live":
            return module("durka_remote_live", "deployment/packmate_remote.py").main(args.live_args)
        if args.action == "doctor":
            # Route before load_config: missing configuration is a reported check,
            # not an invitation to create files or start external services.
            operator = SimpleNamespace(kit=kit, ROOT=ROOT, load_config=load_config,
                                       config_path=config_path, pending=pending, check_config=check_config)
            return module("durka_doctor", "deployment/doctor.py").run(operator, args)
        if args.action == "scan":
            return module("durka_source_scanner", "scripts/defense_scan.py").main(args.scanner_args)
        if args.action == "prepare-clean":
            return prepare_clean(args.config, args.from_config, args.apply)
        if args.action == "init":
            return init(args.config)
        value, paths = load_config(args.config)
        if args.action == "configure":
            return configure(value, paths, args.rollback)
        pending(paths["workspace"])
        if args.action == "setup":
            return setup(value, paths)
        if args.action == "traffic":
            return import_traffic(value, paths, args.file)
        return run_operator(args.action, value, paths)
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Error) else "operation could not complete (" + type(error).__name__ + ")"
        print("ERROR: " + reason, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Existing data is retained; use status before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
