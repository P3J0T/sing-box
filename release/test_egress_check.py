#!/usr/bin/env python3
"""Pipeline-control tests; these stubs are never vulnerability evidence."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

RELEASE = Path(__file__).resolve().parent
GO_STUB = '''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
if args == ['version']:
    print('go version go1.26.11 linux/arm64')
elif args[:1] == ['test']:
    action = os.environ.get('TEST_MUTATION', '')
    if action == 'tracked':
        pathlib.Path('go.mod').write_text('module changed.example\\n')
    elif action == 'untracked':
        pathlib.Path('new_input.go').write_text('package main\\n')
    elif action == 'untracked-change':
        pathlib.Path('new_input.go').write_text('package changed\\n')
    elif action == 'symlink-target':
        pathlib.Path('target.go').write_text('package changed\\n')
    print('ok stub')
elif args[:2] == ['mod', 'verify']:
    if os.environ.get('TEST_MUTATION') == 'go-sum':
        pathlib.Path('go.sum').write_text('changed\\n')
    print('all modules verified (STUB)')
elif args[:1] == ['build']:
    pathlib.Path(args[args.index('-o') + 1]).write_bytes(b'stub binary (NOT a release artifact)')
elif args[:1] == ['list']:
    print('stub module')
else:
    sys.exit(3)
'''
SCANNER_STUB = '''#!/usr/bin/env python3
import os, sys
if 'GOVULNDB' in os.environ or '-db' not in sys.argv or sys.argv[sys.argv.index('-db') + 1] != 'https://vuln.go.dev':
    sys.exit(4)
if '-version' in sys.argv:
    print('Scanner: govulncheck@v1.9.0\\nDB: https://vuln.go.dev\\nDB updated: STUB')
else:
    print('STUB SCANNER RESULT — NOT A VULNERABILITY PASS')
'''


class GateControlTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        (self.repo / 'release').mkdir(parents=True)
        for name in ('egress-check.sh', 'source_manifest.py', 'EGRESS_BUILD_INPUTS'):
            shutil.copyfile(RELEASE / name, self.repo / 'release' / name)
        for name, content in {'go.mod': 'module example.com/fixture\n', 'go.sum': '',
                              'target.go': 'package main\n',
                              'release/LDFLAGS': '', 'release/DEFAULT_BUILD_TAGS_OTHERS': 'test\n'}.items():
            path = self.repo / name
            path.write_text(content)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.repo, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture'], cwd=self.repo, check=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, content in (('go', GO_STUB), ('govulncheck', SCANNER_STUB)):
            path = self.bin / name
            path.write_text(content)
            path.chmod(0o755)

    def gate(self, mutation='', output=None):
        env = os.environ.copy()
        env['PATH'] = str(self.bin) + os.pathsep + env['PATH']
        env['TEST_MUTATION'] = mutation
        env['GOTOOLCHAIN'] = 'local'
        return subprocess.run(['bash', 'release/egress-check.sh', str(output or self.root / 'output')],
                              cwd=self.repo, env=env, text=True, capture_output=True)

    def test_tracked_input_drift(self):
        result = self.gate('tracked')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('source/input drift', result.stderr)
        self.assertFalse((self.root / 'output/SHA256SUMS').exists())

    def test_go_sum_module_stage_drift(self):
        result = self.gate('go-sum')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('go.sum', result.stderr)
        self.assertFalse((self.root / 'output/SHA256SUMS').exists())

    def test_new_untracked_source_drift(self):
        result = self.gate('untracked')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('new_input.go', result.stderr)
        self.assertFalse((self.root / 'output/SHA256SUMS').exists())

    def test_changed_untracked_source_drift(self):
        (self.repo / 'new_input.go').write_text('package main\n')
        result = self.gate('untracked-change')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('new_input.go', result.stderr)

    def test_symlink_alias_source_drift(self):
        (self.repo / 'alias.go').symlink_to('target.go')
        result = self.gate('symlink-target')
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('source/input drift', result.stderr)

    def test_output_parent_symlink_rejected(self):
        (self.repo / 'alias').symlink_to(self.repo / 'release', target_is_directory=True)
        result = self.gate(output=self.repo / 'alias/out')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.repo / 'release/out').exists())

    def test_clean_control_and_receipt_hashes(self):
        original_db = os.environ.get('GOVULNDB')
        os.environ['GOVULNDB'] = 'file:///not-the-default-db'
        self.addCleanup(lambda: os.environ.pop('GOVULNDB', None) if original_db is None else os.environ.__setitem__('GOVULNDB', original_db))
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / 'output'
        sums = (output / 'SHA256SUMS').read_text()
        for name in ('source-manifest.json', 'module-verification.txt', 'build-amd64.txt',
                     'build-arm64.txt', 'scanner-info.txt', 'sing-box-linux-amd64', 'sing-box-linux-arm64'):
            self.assertIn(name, sums)
        self.assertIn('source_digest=', (output / 'provenance.txt').read_text())
        self.assertIn('db_kind=default\ndb_requested=https://vuln.go.dev',
                      (output / 'scanner-info.txt').read_text())
        self.assertIn('STUB', (output / 'vulnerability-amd64.txt').read_text())


if __name__ == '__main__':
    unittest.main()
