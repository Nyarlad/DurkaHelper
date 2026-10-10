"""Read-only host checks for the first Apple Silicon deployment.

Only local metadata and explicit read-only CLI operations are used. In
particular, this module never starts Desktop, executes Neo, or fetches images.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace

GIB = 1024 ** 3


def query(argv, empty_ok=False):
    """Caller supplies fixed read-only commands; suppress all raw diagnostics."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10, check=False)
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            return None
        if result.returncode and not (empty_ok and result.returncode == 1 and not result.stderr and not result.stdout):
            return None
        return result.stdout.decode('utf-8', errors='strict').strip()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None


def neo_arm64(path, kit):
    """Inspect a regular Mach-O header, never execute a downloaded program."""
    path = kit.shared.no_links(Path(path).absolute())
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 32 <= before.st_size <= 64 * 1024 * 1024:
        return False
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, 4096)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            return False
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
            return False
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return False
        if os.name != 'nt' and not opened.st_mode & 0o111:
            return False
        if raw[:4] == b'\xcf\xfa\xed\xfe':
            return struct.unpack_from('<I', raw, 4)[0] == 0x0100000C and struct.unpack_from('<I', raw, 12)[0] == 2
        # Universal executables are accepted only with a bounded ARM64 slice.
        if raw[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
            count = struct.unpack_from('>I', raw, 4)[0]
            width = 20 if raw[:4] == b'\xca\xfe\xba\xbe' else 32
            if not 1 <= count <= 16 or len(raw) < 8 + width * count:
                return False
            for index in range(count):
                position = 8 + width * index
                cpu = struct.unpack_from('>I', raw, position)[0]
                offset, size = struct.unpack_from('>II' if width == 20 else '>QQ', raw, position + 8)
                if cpu == 0x0100000C and offset >= 8 + width * count and size >= 32 and offset + size <= opened.st_size:
                    os.lseek(descriptor, offset, os.SEEK_SET)
                    header = os.read(descriptor, 32)
                    return (header[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack_from('<I', header, 4)[0] == cpu
                            and struct.unpack_from('<I', header, 12)[0] == 2)
        return False
    finally:
        os.close(descriptor)


def inspect(operator, config, neo_client=None):
    kit = operator.kit
    rows = []

    def add(name, status, detail, next_step=''):
        rows.append(dict(check=name, status=status, detail=detail, guidance=next_step))

    mac = platform.system() == 'Darwin'
    machine = platform.machine()
    version = platform.mac_ver()[0] if mac else ''
    add('macOS ARM64', 'READY' if mac and machine == 'arm64' and version else 'BLOCKED',
        ('macOS ' + version + ' / ' + machine) if mac else 'This is not macOS; no Mac compatibility is inferred.',
        'Run on the approved Mac with native ARM64 Python (not a Rosetta shell).')
    add('Python', 'READY' if sys.version_info >= (3, 10) else 'BLOCKED',
        '.'.join(map(str, sys.version_info[:3])), 'Python 3.10+ is required; installation is a separate approved step.')
    git = query(['git', '--version']) if shutil.which('git') else None
    git_match = re.fullmatch(r'git version (\d+)\.(\d+)\.[\w. ()-]+', git or '')
    add('Git', 'READY' if git_match and tuple(map(int, git_match.groups())) >= (2, 30) else 'BLOCKED',
        git if git_match else 'Git unavailable or version could not be verified.', 'Prepare Git 2.30+ before setup.')

    value, paths = None, {'workspace': operator.ROOT / 'local/workspace'}
    try:
        value, paths = operator.load_config(config)
        cfg = operator.config_path(config)
        private = os.name == 'nt' or (not cfg.stat().st_mode & 0o077 and not cfg.parent.stat().st_mode & 0o077)
        expected = {'os': 'darwin', 'architecture': 'arm64', 'runtime': 'docker-desktop'}
        add('Local configuration', 'READY' if private and value['profile']['platform'] == expected else 'BLOCKED',
            'Schema valid; values and credentials are not printed.',
            'Use a private config/directory and the Darwin ARM64 Docker Desktop profile; see the first-run guide.')
        add('Submission safety', 'WARNING', 'Maintained adapter: ructf_http. Do not run submit during acceptance.',
            'Keep the example endpoint/token until protocol compatibility is reviewed; other protocols need separate validation.')
    except (kit.Error, OSError, ValueError, TypeError, KeyError):
        add('Local configuration', 'BLOCKED', 'Missing, invalid, linked or unreadable operator configuration; raw values suppressed.',
            'After approval: python3 durka.py init; edit local/durka.json using the first-run guide.')

    available = bool(shutil.which('docker'))
    add('Docker CLI', 'READY' if available else 'BLOCKED', 'Available.' if available else 'Not found.',
        'Install/start Docker Desktop only after approval; doctor does not start it.')
    desktop = mac and (Path('/Applications/Docker.app').is_dir() or (Path.home() / 'Applications/Docker.app').is_dir())
    add('Docker Desktop application', 'READY' if desktop else 'NOT VERIFIED',
        'Application directory found (not a running-engine test).' if desktop else 'Standard application location not confirmed.',
        'Check the approved installation and Desktop version manually.')
    engine = None
    local = False
    if available:
        # Never inspect a remotely selected daemon as evidence about this laptop.
        endpoint = os.environ.get('DOCKER_HOST') if not os.environ.get('DOCKER_CONTEXT') else None
        if not endpoint:
            endpoint = query(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
        local = bool(endpoint and endpoint.startswith('unix://') and not endpoint[7:].startswith('@'))
        add('Docker endpoint', 'READY' if local else 'BLOCKED',
            'Local Unix socket selected.' if local else 'Local daemon not confirmed; remote queries skipped.',
            'Select the local Desktop context yourself; do not use a remote Engine for this check.')
        if local:
            # Select fields, never dump daemon configuration, proxies or credentials.
            text = query(['docker', 'info', '--format', '{"os":{{json .OSType}},"arch":{{json .Architecture}},"desktop":{{json .OperatingSystem}},"cpus":{{.NCPU}},"memory":{{.MemTotal}}}'])
            try:
                parsed = json.loads(text or '')
                if (isinstance(parsed, dict) and parsed.get('os') == 'linux' and parsed.get('arch') in ('aarch64', 'arm64')
                        and isinstance(parsed.get('cpus'), int) and not isinstance(parsed['cpus'], bool)
                        and isinstance(parsed.get('memory'), int) and not isinstance(parsed['memory'], bool)
                        and isinstance(parsed.get('desktop'), str) and 'docker desktop' in parsed['desktop'].lower()):
                    engine = parsed
            except (ValueError, TypeError, KeyError):
                pass
    add('Docker Desktop Engine', 'READY' if engine else 'BLOCKED',
        'Responsive Linux ARM64 Desktop Engine.' if engine else 'Desktop Engine is stopped, unavailable, or not confirmed as local ARM64.',
        'Open the approved Docker Desktop app and retry; raw Docker output is suppressed.')
    compose = query(['docker', 'compose', 'version', '--short']) if available else None
    compose_match = re.fullmatch(r'v?(\d+)\.(\d+)\.\d+(?:[-+][\w.-]+)?', compose or '')
    add('Compose', 'READY' if compose_match and int(compose_match[1]) >= 2 else 'BLOCKED',
        compose if compose_match else 'Compose version unavailable.', 'Docker Compose v2+ is required.')
    add('Docker resources', 'NOT VERIFIED' if engine is None else 'READY' if engine['cpus'] >= 4 and engine['memory'] >= 8 * GIB else 'WARNING',
        'CPU/RAM allocation unavailable.' if engine is None else f"{engine['cpus']} CPUs / {engine['memory'] / GIB:.1f} GiB allocated.",
        'Start with 4 CPUs / 8 GiB on a 16 GiB laptop; measure stack load before increasing limits.')
    try:
        location = paths['workspace']
        while not location.exists():
            if location.parent == location:
                raise OSError('workspace filesystem unavailable')
            location = location.parent
        free = shutil.disk_usage(location).free
        add('Disk space', 'BLOCKED' if free < 10 * GIB else 'WARNING' if free < 96 * GIB else 'READY',
            f'{free / GIB:.1f} GiB free on the workspace filesystem.',
            'Plan at least 96 GiB for Desktop images/data plus separate backup space; VM disk capacity remains a manual check.')
    except (OSError, ValueError):
        add('Disk space', 'NOT VERIFIED', 'Workspace filesystem capacity unavailable.', 'Check free space and Desktop disk quota manually.')

    ports = sorted(value['profile']['ports'].values()) if value else [8080, 5005, 65000]
    listeners = query(['lsof', '-nP', '-a', '-iTCP:' + ','.join(map(str, ports)), '-sTCP:LISTEN', '-Fn'], empty_ok=True) if mac and shutil.which('lsof') else None
    add('Required TCP ports', 'NOT VERIFIED' if listeners is None else 'WARNING' if listeners else 'READY',
        ', '.join(map(str, ports)) + (': listeners detected; names/addresses suppressed.' if listeners else ': no visible listeners.' if listeners is not None else ': not checked.'),
        'If already running, these may be your services. Resolve conflicts without killing unrelated processes; LAN access still needs two-device testing.')

    prepared = False
    if value and engine and local:
        try:
            operator.pending(paths['workspace'])
            root, _, _, _ = operator.check_config(paths['workspace'], value)
            result = kit.execute(SimpleNamespace(action='preflight', workspace=str(root), runtime=True, apply=False))
            prepared = result.get('runtime') == 'PASS'
        except (kit.Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            pass
    add('Prepared runtime / cached image platforms', 'READY' if prepared else 'BLOCKED',
        'Existing runtime preflight passed: configuration, ownership, immutable cached images and platforms match.' if prepared else 'Not verified; missing cache/build receipt, changed config, or runtime check failed.',
        'After approval and with Internet: setup. If prepared already, use the existing deployment preflight to diagnose; do not rebuild/delete data blindly.')
    add('Packmate emulation', 'WARNING', 'Pinned Packmate is Linux AMD64; Apple Silicon uses emulation. FILE is not continuous LIVE capture.',
        'Measure import latency/storage on the Mac. LIVE needs an approved Linux traffic source; closed PCAP transfer is a fallback only.')
    try:
        binary = Path(neo_client) if neo_client else operator.ROOT / 'local/neo-client/neo'
        client = neo_arm64(binary, kit)
    except (kit.Error, OSError, ValueError, TypeError, struct.error):
        client = False
    add('Neo Darwin ARM64 client', 'READY' if client else 'BLOCKED',
        'Executable ARM64 Mach-O present; header check only, version/auth not proven.' if client else 'Native client missing, non-executable, linked or wrong format/architecture.',
        'Prepare the locked v2.4.2 Darwin ARM64 release before going offline; pass --neo-client PATH if installed elsewhere. Never print neo info on a shared screen.')
    add('Offline / real Mac acceptance', 'NOT VERIFIED', 'Cached-image inspection is not an offline cold start. Hosted CI does not prove Desktop, LAN or local policy compatibility.',
        'Complete MACOS_FIRST_RUN-RU.md and the isolated stack procedure; keep submission disabled. Workers need every script dependency inside their selected image.')
    statuses = {row['status'] for row in rows}
    status = 'BLOCKED' if 'BLOCKED' in statuses else 'WARNING' if 'WARNING' in statuses else 'NOT VERIFIED' if 'NOT VERIFIED' in statuses else 'READY'
    return dict(tool='DurkaHelper doctor', read_only=True, status=status, competition_ready=False,
                exit_code=2 if status == 'BLOCKED' else 1 if status in ('WARNING', 'NOT VERIFIED') else 0, checks=rows)


def run(operator, args):
    report = inspect(operator, args.config, args.neo_client)
    if args.json:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
    else:
        print('DurkaHelper doctor: ' + report['status'] + ' (read-only; not competition certification)')
        for row in report['checks']:
            print(row['status'] + ' | ' + row['check'] + ': ' + row['detail'])
            if row['status'] != 'READY':
                print('  Next: ' + row['guidance'])
    return report['exit_code']
