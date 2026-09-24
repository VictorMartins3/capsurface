"""Download pinned archives, verify integrity, then scan without installing them.

Usage: python3 docs/field-reviews/reproduce.py /absolute/path/to/new-output-directory
Requires Node and the optional pinned parsers installed alongside capsurface.
The output directory must not exist. No target-package code is executed.
"""
import base64
import hashlib
import json
import pathlib
import platform
import subprocess
import sys
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
OUT = pathlib.Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
CLI = str(REPO / 'bin/capsurface.js')

def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def run(cwd, *args):
    start = time.monotonic()
    result = subprocess.run(['node', CLI, *args], cwd=cwd, capture_output=True,
                            text=True, timeout=180)
    return {'command': ['node', '<capsurface>/bin/capsurface.js', *args],
            'elapsedSeconds': round(time.monotonic() - start, 3),
            'exitCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}

write(OUT / 'environment.json', {
    'engineCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(),
    'node': subprocess.check_output(['node', '--version'], text=True).strip(),
    'platform': platform.system(), 'architecture': platform.machine(),
    'scope': 'One published package per snapshot. Transitive dependencies excluded.',
})
for case in json.loads((HERE / 'inputs.json').read_text()):
    dest = OUT / case['name']
    dest.mkdir()
    for side, spec in zip(['before', 'after'], case['versions']):
        data = urllib.request.urlopen(spec['url'], timeout=60).read()
        algorithm, digest = spec['integrity'].split('-', 1)
        actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
        if actual != digest:
            raise ValueError('Archive integrity mismatch: ' + spec['url'])
        (dest / (side + '.tgz')).write_bytes(data)
        write(dest / (side + '-lock.json'), {'name': 'single-package-study', 'lockfileVersion': 3,
            'packages': {'': {'name': 'single-package-study'}, 'node_modules/' + case['name']: {
                'version': spec['version'], 'resolved': spec['url'], 'integrity': spec['integrity']}}})
        write(dest / (side + '-tarballs.json'), {spec['url']: side + '.tgz'})
    for profile in ['basic', 'deep']:
        runs = []
        for side in ['before', 'after']:
            args = ['scan-lock', side + '-lock.json', '--tarballs', side + '-tarballs.json',
                    '--out', profile + '-' + side]
            if profile == 'deep':
                args.append('--deep')
            runs.append(run(dest, *args))
        baseline = profile + '-baseline.json'
        base = run(dest, 'baseline', profile + '-before', '--out', baseline)
        runs.append(base)
        if base['exitCode'] == 0:
            for fmt in ['json', 'markdown']:
                review = run(dest, 'review', profile + '-after', '--baseline', baseline, '--format', fmt)
                runs.append(review)
                (dest / (profile + '-review.' + ('json' if fmt == 'json' else 'md'))).write_text(review['stdout'])
        write(dest / (profile + '-runs.json'), runs)
        print(case['name'], profile, 'exit codes:', [r['exitCode'] for r in runs], flush=True)
