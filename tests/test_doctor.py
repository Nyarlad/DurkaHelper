"""Read-only operator readiness checks; no daemon or target is contacted."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('doctor_operator_test', ROOT / 'durka.py')
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)
doctor = operator.module('doctor_unit_test', 'deployment/doctor.py')


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.config = self.root / 'durka.json'
        self.config.write_text('{}', encoding='utf-8')
        self.config.chmod(0o600)
        self.binary = self.root / 'neo'
        self.binary.write_bytes(struct.pack('<IIII', 0xFEEDFACF, 0x0100000C, 0, 2) + bytes(16))
        self.binary.chmod(0o700)
        self.value = json.loads((ROOT / 'config/durka.example.json').read_text(encoding='utf-8'))
        self.value['credentials'] = {'canary': 'NEVER-PRINT-THIS-SECRET'}
        self.paths = {'workspace': self.root / 'workspace', 'sources': self.root / 'sources'}
        self.api = SimpleNamespace(kit=operator.kit, ROOT=self.root,
                                   load_config=mock.Mock(return_value=(self.value, self.paths)),
                                   config_path=mock.Mock(return_value=self.config),
                                   pending=mock.Mock(), check_config=mock.Mock(return_value=(self.root, {}, {}, {})))
        self.commands = []
        self.info = dict(os='linux', arch='aarch64', desktop='Docker Desktop', cpus=4, memory=8 * doctor.GIB)

    def response(self, command, **kwargs):
        self.commands.append(command)
        if command == ['git', '--version']:
            return 'git version 2.53.0'
        if command[:3] == ['docker', 'context', 'inspect']:
            return 'unix:///private/var/run/docker.sock'
        if command[:2] == ['docker', 'info']:
            return json.dumps(self.info)
        if command == ['docker', 'compose', 'version', '--short']:
            return 'v2.40.3'
        if command[0] == 'lsof':
            return ''
        self.fail('Unexpected command: ' + repr(command))

    def report(self, system='Darwin', machine='arm64', free=120 * doctor.GIB, endpoint=''):
        with mock.patch.object(doctor.platform, 'system', return_value=system), \
                mock.patch.object(doctor.platform, 'machine', return_value=machine), \
                mock.patch.object(doctor.platform, 'mac_ver', return_value=('15.7', (), '')), \
                mock.patch.object(doctor.shutil, 'which', return_value='/trusted/tool'), \
                mock.patch.object(doctor.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)), \
                mock.patch.object(doctor, 'query', side_effect=self.response), \
                mock.patch.object(operator.kit, 'execute', return_value={'runtime': 'PASS'}) as preflight, \
                mock.patch.dict(os.environ, {'DOCKER_HOST': endpoint, 'DOCKER_CONTEXT': ''}):
            report = doctor.inspect(self.api, self.config, self.binary)
        return report, preflight

    @staticmethod
    def checks(report):
        return {row['check']: row for row in report['checks']}

    def test_host_config_and_cache_reuse_read_only_preflight(self):
        report, preflight = self.report()
        checks = self.checks(report)
        for name in ('macOS ARM64', 'Python', 'Git', 'Local configuration', 'Docker CLI', 'Docker endpoint',
                     'Docker Desktop Engine', 'Compose', 'Docker resources', 'Disk space', 'Required TCP ports',
                     'Prepared runtime / cached image platforms', 'Neo Darwin ARM64 client'):
            self.assertEqual(checks[name]['status'], 'READY', name)
        self.assertTrue(report['read_only'])
        self.assertFalse(report['competition_ready'])
        self.assertEqual(report['status'], 'WARNING')
        self.assertEqual(report['exit_code'], 1)
        self.assertFalse(preflight.call_args.args[0].apply)
        self.assertEqual(preflight.call_args.args[0].action, 'preflight')
        self.assertNotIn('NEVER-PRINT-THIS-SECRET', json.dumps(report))

    def test_cli_routes_without_mutating_or_requiring_configuration(self):
        module = SimpleNamespace(run=mock.Mock(return_value=2))
        with mock.patch.object(operator, 'module', return_value=module), \
                mock.patch.object(operator, 'load_config') as config, \
                mock.patch.object(operator, 'init') as init:
            self.assertEqual(operator.main(['doctor', '--json', '--neo-client', str(self.binary)]), 2)
        config.assert_not_called()
        init.assert_not_called()
        self.assertTrue(module.run.call_args.args[1].json)

    def test_missing_config_is_structured_and_does_not_initialize(self):
        self.api.load_config.side_effect = operator.Error('SECRET internal error')
        report, preflight = self.report()
        self.assertEqual(self.checks(report)['Local configuration']['status'], 'BLOCKED')
        self.assertEqual(report['exit_code'], 2)
        self.assertNotIn('SECRET', json.dumps(report))
        preflight.assert_not_called()

    def test_actual_host_not_configuration_fallback_controls_mac_status(self):
        for system, machine in (('Windows', 'AMD64'), ('Linux', 'aarch64'), ('Darwin', 'x86_64')):
            report, _ = self.report(system=system, machine=machine)
            self.assertEqual(self.checks(report)['macOS ARM64']['status'], 'BLOCKED')

    def test_low_disk_space_is_blocked_not_ready(self):
        for free, expected in ((5 * doctor.GIB, 'BLOCKED'), (20 * doctor.GIB, 'WARNING')):
            report, _ = self.report(free=free)
            self.assertEqual(self.checks(report)['Disk space']['status'], expected)

    def test_remote_docker_host_override_skips_context_and_daemon(self):
        report, preflight = self.report(endpoint='tcp://example.invalid:2376')
        self.assertEqual(self.checks(report)['Docker endpoint']['status'], 'BLOCKED')
        self.assertFalse(any(cmd[:2] in (['docker', 'info'], ['docker', 'context']) for cmd in self.commands))
        preflight.assert_not_called()

    def test_port_inspection_failure_is_not_verified(self):
        original = self.response
        self.response = lambda command, **kwargs: None if command[0] == 'lsof' else original(command, **kwargs)
        report, _ = self.report()
        self.assertEqual(self.checks(report)['Required TCP ports']['status'], 'NOT VERIFIED')

    def test_remote_daemon_is_not_inspected(self):
        original = self.response

        def remote(command, **kwargs):
            if command[:3] == ['docker', 'context', 'inspect']:
                self.commands.append(command)
                return 'ssh://private-user@private-host'
            return original(command, **kwargs)

        self.response = remote
        report, preflight = self.report()
        self.assertEqual(self.checks(report)['Docker endpoint']['status'], 'BLOCKED')
        self.assertFalse(any(cmd[:2] == ['docker', 'info'] for cmd in self.commands))
        self.assertNotIn('private-host', json.dumps(report))
        preflight.assert_not_called()

    def test_stopped_engine_or_wrong_arch_is_blocked_without_runtime_inspection(self):
        for info in ({}, dict(self.info, arch='x86_64'), dict(self.info, desktop='Ubuntu')):
            self.info = info
            report, preflight = self.report()
            self.assertEqual(self.checks(report)['Docker Desktop Engine']['status'], 'BLOCKED')
            preflight.assert_not_called()

    def test_resource_shortage_and_occupied_ports_are_actionable(self):
        self.info.update(cpus=2, memory=4 * doctor.GIB)
        original = self.response
        self.response = lambda command, **kwargs: 'p123\nnPRIVATE_ADDRESS' if command[0] == 'lsof' else original(command, **kwargs)
        report, _ = self.report()
        checks = self.checks(report)
        self.assertEqual(checks['Docker resources']['status'], 'WARNING')
        self.assertEqual(checks['Required TCP ports']['status'], 'WARNING')
        self.assertNotIn('PRIVATE_ADDRESS', json.dumps(report))

    def test_changed_or_missing_runtime_receipt_is_not_false_clean(self):
        self.api.check_config.side_effect = operator.Error('SECRET build problem')
        report, preflight = self.report()
        self.assertEqual(self.checks(report)['Prepared runtime / cached image platforms']['status'], 'BLOCKED')
        self.assertNotIn('SECRET', json.dumps(report))
        preflight.assert_not_called()

    def test_no_network_writes_or_target_execution(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('No network')), \
                mock.patch.object(Path, 'write_text', side_effect=AssertionError('No write')), \
                mock.patch.object(Path, 'write_bytes', side_effect=AssertionError('No write')), \
                mock.patch.object(Path, 'mkdir', side_effect=AssertionError('No mkdir')), \
                mock.patch.object(operator.kit.shared, 'write', side_effect=AssertionError('No write')):
            self.report()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()})
        allowed = {('git', '--version'), ('docker', 'context', 'inspect'), ('docker', 'info', '--format'),
                   ('docker', 'compose', 'version'), ('lsof', '-nP', '-a')}
        self.assertTrue(all(tuple(cmd[:3]) in allowed or tuple(cmd) in allowed for cmd in self.commands))

    def test_neo_header_rejects_wrong_arch_nonexecutables_and_non_executable_macho(self):
        for data in (b'\x7fELF' + bytes(28), bytes(32), struct.pack('<IIII', 0xFEEDFACF, 0x01000007, 0, 2) + bytes(16),
                     struct.pack('<IIII', 0xFEEDFACF, 0x0100000C, 0, 6) + bytes(16)):
            self.binary.write_bytes(data)
            self.assertFalse(doctor.neo_arm64(self.binary, operator.kit))

    def test_neo_fat_header_checks_actual_arm64_slice(self):
        header = self.binary.read_bytes()
        fat = struct.pack('>II', 0xCAFEBABE, 1) + struct.pack('>IIIII', 0x0100000C, 0, 28, 32, 0)
        self.binary.write_bytes(fat + header)
        self.assertTrue(doctor.neo_arm64(self.binary, operator.kit))
        self.binary.write_bytes(fat + bytes(32))
        self.assertFalse(doctor.neo_arm64(self.binary, operator.kit))

    def test_neo_missing_is_blocked(self):
        self.binary.unlink()
        report, _ = self.report()
        self.assertEqual(self.checks(report)['Neo Darwin ARM64 client']['status'], 'BLOCKED')

    def test_query_suppresses_stderr_errors_timeouts_and_oversized_output(self):
        for result in (SimpleNamespace(returncode=2, stdout=b'SECRET', stderr=b'SECRET'),
                       SimpleNamespace(returncode=0, stdout=b'x' * 65537, stderr=b'')):
            with mock.patch.object(doctor.subprocess, 'run', return_value=result):
                self.assertIsNone(doctor.query(['git', '--version']))
        with mock.patch.object(doctor.subprocess, 'run', side_effect=subprocess.TimeoutExpired('git', 10)):
            self.assertIsNone(doctor.query(['git', '--version']))
        with mock.patch.object(doctor.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'', stderr=b'')):
            self.assertEqual(doctor.query(['lsof'], empty_ok=True), '')

    def test_text_and_json_reports_do_not_echo_inputs(self):
        report, _ = self.report()
        for machine in (False, True):
            stream = io.StringIO()
            with mock.patch.object(doctor, 'inspect', return_value=report), contextlib.redirect_stdout(stream):
                self.assertEqual(doctor.run(self.api, SimpleNamespace(config=self.config, neo_client=self.binary, json=machine)), 1)
            self.assertIn('WARNING', stream.getvalue())
            self.assertNotIn('NEVER-PRINT-THIS-SECRET', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
