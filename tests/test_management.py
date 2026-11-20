import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_pi', ROOT / 'scripts/check_pi.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ConnectionTests(unittest.TestCase):
    def verify(self, runner, **changes):
        args = dict(config=Path('/example/private config'), alias='pi-management', host='lab-pi',
                    user='pi', arch='armv7l', bits=32, run=runner)
        args.update(changes)
        return check.verify(**args)

    def test_success_uses_strict_noninteractive_ssh(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, check.MARKER+'\n', ''))
        self.assertTrue(self.verify(runner))
        argv = runner.call_args.args[0]
        self.assertEqual(argv[:4], ['ssh', '-T', '-F', '/example/private config'])
        for value in ['StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                      'PreferredAuthentications=publickey', 'PubkeyAuthentication=yes',
                      'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                      'ForwardAgent=no', 'ForwardX11=no', 'ClearAllForwardings=yes',
                      'RequestTTY=no', 'PermitLocalCommand=no']:
            self.assertIn(value, argv)
        self.assertEqual(argv[-3:], ['--', 'pi-management', 'sh -s -- lab-pi pi armv7l 32'])
        self.assertEqual(runner.call_args.kwargs['input'], check.REMOTE)
        self.assertNotIn('shell', runner.call_args.kwargs)

    def test_authentication_failure_has_no_local_retry(self):
        runner = Mock(return_value=subprocess.CompletedProcess([], 255, '', 'SYNTHETIC_PRIVATE_DETAILS'))
        self.assertFalse(self.verify(runner))
        runner.assert_called_once()

    def test_wrong_marker_and_extra_output_do_not_pass(self):
        for text in ['', 'different target', check.MARKER+'\nextra output']:
            runner = Mock(return_value=subprocess.CompletedProcess([], 0, text, ''))
            self.assertFalse(self.verify(runner))

    def test_timeout_and_missing_ssh_fail_closed(self):
        for error in [subprocess.TimeoutExpired('ssh', 25), FileNotFoundError()]:
            runner = Mock(side_effect=error)
            self.assertFalse(self.verify(runner))
            runner.assert_called_once()

    def test_option_injection_and_shell_metacharacters_are_rejected(self):
        for changes in [{'alias': '-oProxyCommand=unexpected'}, {'host': 'pi;echo unsafe'},
                        {'user': 'pi\nother'}, {'bits': 16}]:
            runner = Mock()
            self.assertFalse(self.verify(runner, **changes))
            runner.assert_not_called()

    def test_cli_failure_output_excludes_target_details(self):
        args = ['check_pi.py', '--config', '/PRIVATE_SENTINEL/config', '--alias', 'private-sentinel',
                '--host', 'private-sentinel', '--user', 'pi', '--arch', 'armv7l', '--bits', '32']
        stdout = io.StringIO()
        with patch.object(sys, 'argv', args), patch.object(check, 'verify', return_value=False), contextlib.redirect_stdout(stdout):
            self.assertEqual(check.main(), 1)
        self.assertNotIn('sentinel', stdout.getvalue().lower())


class RemoteIdentityTests(unittest.TestCase):
    def run_remote(self, host='lab-pi', user='pi', arch='armv7l', bits='32'):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, output in [('hostname', host), ('id', user), ('uname', arch), ('getconf', bits)]:
                p = root / name
                p.write_text("#!/bin/sh\nprintf '%s\\n' '"+output+"'\n")
                p.chmod(0o700)
            env = dict(os.environ, PATH=str(root))
            return subprocess.run(['/bin/sh', '-s', '--', 'lab-pi', 'pi', 'armv7l', '32'],
                                  input=check.REMOTE, capture_output=True, text=True, env=env, timeout=5)

    def test_expected_identity_passes(self):
        result = self.run_remote()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), check.MARKER)

    def test_each_identity_mismatch_stops_success(self):
        for changes in [{'host': 'other-pi'}, {'user': 'other-user'}, {'arch': 'aarch64'}, {'bits': '64'}]:
            with self.subTest(changes=changes):
                result = self.run_remote(**changes)
                self.assertEqual(result.returncode, 41)
                self.assertEqual(result.stdout, '')


FAKE = '''import json, os, sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
log=Path(os.environ['FAKE_RULE_LOG'])
with log.open('a') as stream: stream.write(json.dumps({'tool':name,'args':args})+'\\n')
state=Path(os.environ['FAKE_RULE_STATE'])
installed=json.loads(state.read_text()) if state.exists() else []
if '-C' in args: raise SystemExit(0 if name in installed else 1)
if '-I' in args:
    if name==os.environ.get('FAKE_FAIL_TOOL'): raise SystemExit(3)
    if name not in installed: installed.append(name)
    state.write_text(json.dumps(installed))
    raise SystemExit(0)
raise SystemExit(99)
'''


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log, self.state = self.root/'calls.jsonl', self.root/'rules.json'
        source = (ROOT / 'firewall/ssh-tailnet-guard.sh').read_text()
        for name in ['iptables', 'ip6tables']:
            p = self.root / name
            p.write_text('#!'+sys.executable+'\n'+FAKE)
            p.chmod(0o700)
            source = source.replace('/usr/sbin/'+name, str(p))
        # Refuse to execute if an actual firewall command path survived rewriting.
        self.assertNotIn('/usr/sbin/', source)
        self.script = self.root/'guard.sh'
        self.script.write_text(source)
        self.env = dict(os.environ, FAKE_RULE_LOG=str(self.log), FAKE_RULE_STATE=str(self.state))

    def run_guard(self):
        return subprocess.run(['/bin/sh', str(self.script)], capture_output=True, text=True, env=self.env, timeout=5)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_both_families_insert_only_tagged_non_tailnet_tcp22_rule(self):
        self.assertEqual(self.run_guard().returncode, 0)
        insertions = [c for c in self.calls() if '-I' in c['args']]
        self.assertEqual({c['tool'] for c in insertions}, {'iptables', 'ip6tables'})
        for call in insertions:
            self.assertEqual(call['args'], ['-w','5','-I','INPUT','1','!','-i','tailscale0',
                '-p','tcp','--dport','22','-m','comment','--comment','pi-management-tailnet-only','-j','DROP'])

    def test_existing_rules_do_not_duplicate_or_flush(self):
        self.assertEqual(self.run_guard().returncode, 0)
        self.assertEqual(self.run_guard().returncode, 0)
        calls = self.calls()
        self.assertEqual(sum('-I' in c['args'] for c in calls), 2)
        self.assertFalse(any('-F' in c['args'] or '--flush' in c['args'] for c in calls))

    def test_first_family_failure_stops_guard(self):
        self.env['FAKE_FAIL_TOOL'] = 'iptables'
        self.assertNotEqual(self.run_guard().returncode, 0)
        self.assertFalse(any(c['tool']=='ip6tables' for c in self.calls()))

    def test_second_family_failure_is_not_reported_as_success(self):
        self.env['FAKE_FAIL_TOOL'] = 'ip6tables'
        self.assertNotEqual(self.run_guard().returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), ['iptables'])


if __name__ == '__main__':
    unittest.main()
