"""Check release files for private data, unexpected entries and missing content.

Set BZAP_PRIVATE_TERMS to a semicolon-separated local denylist.
"""
from pathlib import Path, PureWindowsPath
import hashlib
import os
import re
import stat
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', 'build', 'dist', 'release', '.toolchain', '__pycache__', '.venv'}
RUNTIME = {'BandizipAutoPassword.exe', 'ark.x64.dll', 'README.md', 'LICENSE',
           'MbedTLS-LICENSE.txt', 'THIRD_PARTY_NOTICES.txt'}
RUNTIME_DOCS = {'docs/AUDIT.md', 'assets/manager.png'}
SOURCE = {'src/proxy.cpp', 'src/common.hpp', 'README.md', 'LICENSE'}
SOURCE_BUILD = SOURCE | {'build.ps1', 'src/common.cpp', 'src/manager.cpp', 'src/manager.rc',
                         'src/installer.cpp', 'src/password_store.cpp', 'src/reporting.cpp',
                         'src/recycle.cpp', 'assets/app.ico', 'third_party/mbedtls/library/blowfish.c',
                         'third_party/mbedtls/LICENSE'}
FORBIDDEN = {'.pdb', '.log', '.dmp', '.jsonl', '.previous'}
PRIVATE_NAMES = {'解压记录.txt', 'settings.ini', 'installation.ini'}
PRIVATE_PATTERNS = (
    re.compile(r'(?i)[A-Z]:[\\/](?:Users|Documents|Project)[\\/]'),
    re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}'),
)
PACKAGE_NAME = re.compile(r'(BandizipAutoPassword-\d+\.\d+\.\d+)-(source|windows-x64)\.zip')


def check_bytes(name, data):
    problems = []
    terms = [x.casefold() for x in os.environ.get('BZAP_PRIVATE_TERMS', '').split(';') if x]
    texts = (name, data.decode('utf8', errors='ignore'), data.decode('utf-16-le', errors='ignore'),
             data[1:].decode('utf-16-le', errors='ignore'))
    for value in texts:
        if any(p.search(value) for p in PRIVATE_PATTERNS) or any(t in value.casefold() for t in terms):
            problems.append(name)
            break
    if data.startswith(b'MZ'):
        try:
            pe, = struct.unpack_from('<I', data, 60)
            optional = pe + 24
            magic, = struct.unpack_from('<H', data, optional)
            if data[pe:pe + 4] != b'PE\0\0' or magic not in (0x20b, 0x10b):
                raise ValueError('Invalid PE header')
            directories = optional + (112 if magic == 0x20b else 96)
            if any(struct.unpack_from('<II', data, directories + 6 * 8)):
                problems.append(name + ' (debug directory)')
        except (ValueError, struct.error):
            problems.append(name + ' (invalid PE)')
    return problems


def require_files(label, sizes, required):
    missing = sorted(name for name in required if sizes.get(name, 0) == 0)
    return [f'{label} (missing or empty: {", ".join(missing)})'] if missing else []


def forbidden(name):
    path = PureWindowsPath(name)
    return path.suffix.lower() in FORBIDDEN or path.name.lower() in PRIVATE_NAMES


def check_zip(path):
    errors = []
    names = set()
    sizes = {}
    with zipfile.ZipFile(path) as archive:
        errors.extend(check_bytes(path.name, archive.comment))
        for entry in archive.infolist():
            name = entry.filename
            normalized = name.rstrip('/').casefold()
            if (normalized in names or '\\' in name or PureWindowsPath(name).anchor
                    or any(part in ('', '.', '..') or ':' in part for part in name.rstrip('/').split('/'))
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                errors.append(f'{path.name} (ambiguous or unsafe entry: {name})')
            names.add(normalized)
            errors.extend(check_bytes(name, entry.comment + entry.extra))
            if entry.is_dir():
                continue
            sizes[name] = entry.file_size
            # Read the actual central directory entry, including duplicates.
            errors.extend(check_bytes(name, archive.read(entry)))
            if forbidden(name):
                errors.append(name)
    published = PACKAGE_NAME.fullmatch(path.name)
    roots = [n[:-len('src/proxy.cpp')] for n in sizes if n == 'src/proxy.cpp' or n.endswith('/src/proxy.cpp')]
    source = published[2] == 'source' if published else bool(roots)
    if source:
        if len(roots) != 1 or (published and roots != ['BandizipAutoPassword-source/']):
            errors.append(path.name + ' (invalid source layout)')
        else:
            prefix = roots[0]
            required = SOURCE_BUILD if published else SOURCE
            errors.extend(require_files(path.name, sizes, {prefix + n for n in required}))
            if any(not n.startswith(prefix) for n in sizes):
                errors.append(path.name + ' (unexpected source root)')
    else:
        required = RUNTIME | RUNTIME_DOCS if published else RUNTIME
        errors.extend(require_files(path.name, sizes, required))
        if published and sizes.keys() - required:
            errors.append(path.name + ' (unexpected runtime files)')
    return errors, len(sizes)


def check_bundle(root, entries):
    names = {p.relative_to(root).as_posix() for p in entries}
    packages = [PACKAGE_NAME.fullmatch(n) for n in names if n.lower().endswith('.zip')]
    if len(packages) != 2 or not all(packages) or packages[0][1] != packages[1][1]:
        return ['Incomplete release: expected matching runtime and source ZIPs']
    base = packages[0][1]
    pair = {base + '-source.zip', base + '-windows-x64.zip'}
    if names != pair | {'SHA256SUMS.txt'}:
        return ['Incomplete or mixed release directory']
    expected = {hashlib.sha256((root / n).read_bytes()).hexdigest() + '  ' + n for n in pair}
    lines = (root / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines()
    return [] if len(lines) == 2 and set(lines) == expected else ['SHA256SUMS.txt (checksum mismatch)']


def linked(path):
    attrs = getattr(path.lstat(), 'st_file_attributes', 0)
    return path.is_symlink() or bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def raise_walk_error(error):
    raise error


def check_artifacts(path):
    path = Path(path)
    errors = []
    count = 0
    try:
        if linked(path):
            return [str(path) + ' (link)'], 0
        entries = []
        if path.is_dir():
            for folder, dirs, files in os.walk(path, onerror=raise_walk_error):
                for name in dirs.copy():
                    if linked(Path(folder) / name):
                        errors.append(name + ' (linked directory)')
                        dirs.remove(name)
                entries.extend(Path(folder) / name for name in files)
        else:
            entries = [path]
        sizes = {}
        for item in entries:
            if linked(item) or not item.is_file():
                errors.append(item.name + ' (not a regular file)')
                continue
            if item.suffix.lower() == '.zip':
                found, scanned = check_zip(item)
                errors.extend(found)
                count += scanned
            else:
                name = item.relative_to(path).as_posix() if path.is_dir() else item.name
                data = item.read_bytes()
                sizes[name] = len(data)
                count += 1
                errors.extend(check_bytes(name, data))
                if forbidden(name):
                    errors.append(name)
        if path.is_dir() and not errors:
            if any(x.suffix.lower() == '.zip' for x in entries):
                errors.extend(check_bundle(path, entries))
            else:
                errors.extend(require_files(str(path), sizes, RUNTIME))
        if not count:
            errors.append(str(path) + ' (no artifact files scanned)')
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        errors.append(str(path) + ' (unreadable: ' + type(error).__name__ + ')')
    return errors, count


def main():
    failures = []
    count = 0
    for directory, dirs, names in os.walk(ROOT, onerror=raise_walk_error):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in dirs.copy():
            if linked(Path(directory) / name):
                failures.append(name + ' (linked source directory)')
                dirs.remove(name)
        for name in names:
            if name == '.git':
                continue
            path = Path(directory) / name
            relative = path.relative_to(ROOT).as_posix()
            if linked(path) or forbidden(relative):
                failures.append(relative)
                continue
            failures.extend(check_bytes(relative, path.read_bytes()))
            count += 1
    for arg in sys.argv[1:] or [ROOT / 'release']:
        found, scanned = check_artifacts(arg)
        failures.extend(found)
        count += scanned
    if failures:
        print('Privacy check FAILED: ' + ', '.join(sorted(set(failures))))
        return 1
    print(f'Privacy check passed: {count} files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
