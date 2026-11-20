#!/usr/bin/env python3
"""Explicit, read-only remote identity check over strictly authenticated SSH."""
import argparse
from pathlib import Path
import re
import shlex
import subprocess

MARKER = 'PI_MANAGEMENT_IDENTITY_OK'
REMOTE = '''set -eu
[ "$(hostname)" = "$1" ] &&
[ "$(id -un)" = "$2" ] &&
[ "$(uname -m)" = "$3" ] &&
[ "$(getconf LONG_BIT)" = "$4" ] || exit 41
printf '%s\\n' 'PI_MANAGEMENT_IDENTITY_OK'
'''
OPTIONS = [
    'BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes',
    'PreferredAuthentications=publickey', 'PubkeyAuthentication=yes',
    'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
    'ForwardAgent=no', 'ForwardX11=no', 'ClearAllForwardings=yes',
    'RequestTTY=no', 'PermitLocalCommand=no', 'ConnectTimeout=10',
]


def verify(config, alias, host, user, arch, bits, run=subprocess.run):
    values = [alias, host, user, arch]
    if not all(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', v) for v in values) or bits not in (32, 64):
        return False
    args = ['ssh', '-T', '-F', str(config)]
    for option in OPTIONS:
        args.extend(['-o', option])
    remote = shlex.join(['sh', '-s', '--', host, user, arch, str(bits)])
    args.extend(['--', alias, remote])
    try:
        result = run(args, input=REMOTE, capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == MARKER


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--alias', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--arch', required=True)
    parser.add_argument('--bits', type=int, choices=[32, 64], required=True)
    args = parser.parse_args()
    if verify(args.config, args.alias, args.host, args.user, args.arch, args.bits):
        print('Remote hostname, account, architecture and userspace verified.')
        return 0
    print('Remote verification failed. Review target identity and host-key trust privately.')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
