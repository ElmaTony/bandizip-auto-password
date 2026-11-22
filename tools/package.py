"""Package tracked source and an explicit runtime allowlist; never bundle Bandizip."""
from pathlib import Path
import argparse
import hashlib
import re
import shutil
import subprocess
import uuid
import zipfile

from privacy_check import RUNTIME, RUNTIME_DOCS, check_artifacts, check_bytes, forbidden

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


def write_archives(output, commit):
    binary = output / f'BandizipAutoPassword-{VERSION}-windows-x64.zip'
    source = output / f'BandizipAutoPassword-{VERSION}-source.zip'
    with zipfile.ZipFile(binary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(RUNTIME | RUNTIME_DOCS):
            add(archive, ROOT / 'release' / name, name)
    tracked = subprocess.check_output(['git', 'ls-tree', '-rz', commit], cwd=ROOT).decode('utf8').split('\0')
    with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for entry in filter(None, tracked):
            metadata, name = entry.split('\t', 1)
            mode, kind, blob = metadata.split()
            path = ROOT / name
            if kind != 'blob' or mode not in {'100644', '100755'} or any(
                    p in {'build', 'dist', 'release', '.toolchain', '.git'} for p in Path(name).parts):
                raise ValueError('Unexpected tracked artifact: ' + name)
            if forbidden(name) or path.suffix.lower() in {'.exe', '.dll', '.zip', '.o', '.obj', '.lib'}:
                raise ValueError('Unexpected tracked binary/log: ' + name)
            data = subprocess.check_output(['git', 'cat-file', 'blob', blob], cwd=ROOT)
            add(archive, path, 'BandizipAutoPassword-source/' + name, data)
    checksums = ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                        for path in [binary, source])
    (output / 'SHA256SUMS.txt').write_text(checksums, encoding='utf8', newline='\n')
    return checksums


def publish_archives(output, commit):
    output.parent.mkdir(parents=True, exist_ok=True)
    # The published directory must inherit access from the chosen destination.
    # A child of mkdtemp() keeps its owner-only Windows ACL after a rename.
    staging = output.parent / ('.bzap-package-' + uuid.uuid4().hex)
    staging.mkdir()
    try:
        checksums = write_archives(staging, commit)
        errors, _ = check_artifacts(staging)
        if errors:
            raise ValueError('Release validation failed: ' + ', '.join(errors))
        if output.exists():
            output.rmdir()  # Accept only an empty destination, including at commit time.
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    return checksums


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output.resolve()
    if output == ROOT or ROOT in output.parents or output in ROOT.parents:
        raise ValueError('Choose a separate release directory outside the project.')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('The release destination must be new or empty.')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT):
        raise ValueError('Commit the intended source before packaging.')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    print(publish_archives(output, commit), end='')


if __name__ == '__main__':
    main()
