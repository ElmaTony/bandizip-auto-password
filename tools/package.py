"""Package tracked source and an explicit runtime allowlist; never bundle Bandizip."""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess
import zipfile

from privacy_check import check_bytes

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r'ProductVersion\[\]\s*=\s*L"([0-9.]+)"',
                    (ROOT / 'src/common.hpp').read_text('utf8'))[1]


def add(archive, path, name, data=None):
    if data is None:
        data = path.read_bytes()
    problems = check_bytes(name, data)
    if problems:
        raise ValueError('Privacy check failed: ' + ', '.join(problems))
    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('Place release archives outside the source project.')
    output.mkdir(parents=True, exist_ok=True)
    runtime = ['BandizipAutoPassword.exe', 'ark.x64.dll', 'README.md',
               'THIRD_PARTY_NOTICES.txt', 'MbedTLS-LICENSE.txt', 'LICENSE']
    binary = output / f'BandizipAutoPassword-{VERSION}-windows-x64.zip'
    source = output / f'BandizipAutoPassword-{VERSION}-source.zip'
    with zipfile.ZipFile(binary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in runtime:
            add(archive, ROOT / 'release' / name, name)
        for name in ['docs/AUDIT.md', 'assets/manager.png']:
            add(archive, ROOT / name, name)
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf8').split('\0')
    if not any(name == 'src/proxy.cpp' for name in tracked):
        raise ValueError('Stage the complete source tree before packaging.')
    subprocess.run(['git', 'diff', '--exit-code', '--quiet'], cwd=ROOT, check=True)
    with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(filter(None, tracked)):
            path = ROOT / name
            if path.is_symlink() or any(p in {'build', 'dist', 'release', '.toolchain', '.git'} for p in path.relative_to(ROOT).parts):
                raise ValueError('Unexpected tracked artifact: ' + name)
            if path.suffix.lower() in {'.exe', '.dll', '.pdb', '.log', '.zip', '.jsonl', '.dmp', '.o', '.obj', '.lib'}:
                raise ValueError('Unexpected tracked binary/log: ' + name)
            data = subprocess.check_output(['git', 'show', ':' + name], cwd=ROOT)
            add(archive, path, 'BandizipAutoPassword-source/' + name, data)
    checksums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                        for path in [binary, source])
    (output / 'SHA256SUMS.txt').write_text(checksums, encoding='utf8', newline='\n')
    print(checksums, end='')


if __name__ == '__main__':
    main()
