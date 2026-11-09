"""Real recycle-bin checks on isolated fixtures. Recycled fixtures are restored afterward."""
from pathlib import Path
import hashlib
import os
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run_recycle_tests(app, source, fixtures, work, data, zig, run, check, history, trace):
    cases = work / 'recycle-cases'
    cases.mkdir()
    settings = data / 'settings.ini'
    restore = work / 'recycle-restore.exe'
    r = run([zig, 'c++', '-target', 'x86_64-windows-gnu', '-march=x86_64', '-std=c++17', '-O2',
             '-static', '-municode', '-Isrc', ROOT / 'tests/recycle_restore.cpp', ROOT / 'src/common.cpp',
             '-lole32', '-lshell32', '-luuid', '-ladvapi32', '-lbcrypt', '-lversion', '-o', restore], timeout=120)
    check('recycle-restore-driver', r.returncode == 0)
    def enable(value=True, password_matching=True):
        settings.write_text('[General]\nEnabled=' + str(int(password_matching)) + '\nNotifyFailures=0\n'
                            'FullPreflight=0\nRecycleAfterExtract=' + str(int(value)) + '\n', 'utf8')
    def hashes(paths):
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    def extract(label, archive, inputs, recycle, extras=(), matching=True):
        before = len(history())
        saved = hashes(inputs)
        enable(True, matching)
        target = cases / (label + '-out')
        command = [app / 'Bandizip.exe', 'x', '-y', '-o:' + str(target), archive, *extras]
        r = run(command, timeout=35)
        records = history()[before:]
        if recycle:
            check(label, r.returncode < 0x80000000 and all(not p.exists() for p in inputs) and
                  any(x['outcome'] == 'recycled' and x['recycled_volumes'] == len(inputs) for x in records),
                  records=records)
        else:
            check(label, r.returncode < 0x80000000 and all(p.exists() for p in inputs) and hashes(inputs) == saved,
                  records=records)
        return saved
    try:
        for label, name, recycle, matching in [
            ('recycle-encrypted', 'saved.zip', True, True),
            ('recycle-plain', 'plain.zip', True, True),
            ('recycle-independent-setting', 'plain.zip', True, False),
            ('recycle-wrong-password-kept', 'unknown.zip', False, True),
            ('recycle-damaged-kept', 'damaged.zip', False, True),
        ]:
            archive = cases / (label + '.zip')
            shutil.copy2(fixtures / name, archive)
            extract(label, archive, [archive], recycle, matching=matching)
        archive = cases / 'selected.zip'
        shutil.copy2(fixtures / 'mixed-known.zip', archive)
        extract('recycle-selected-kept', archive, [archive], False, extras=['proof.txt'])
        check('selected-engine-path', (cases / 'recycle-selected-kept-out/proof.txt').exists() and
              not (cases / 'recycle-selected-kept-out/other.txt').exists())
        archive = cases / 'skip.zip'
        shutil.copy2(fixtures / 'plain.zip', archive)
        target = cases / 'recycle-skipped-kept-out'
        target.mkdir(); (target / 'proof.txt').write_bytes(b'keep existing output')
        extract('recycle-skipped-kept', archive, [archive], False, extras=['-aos'])
        payload = cases / 'payload.bin'
        payload.write_bytes(os.urandom(150000))
        for fmt in ['7z', 'zip']:
            folder = cases / ('split-' + fmt); folder.mkdir()
            archive = folder / ('分卷 test.' + fmt)
            r = run([source / 'bz.exe', 'c', '-fmt:' + fmt, '-l:0', '-v:32768', '-p:fixture-secret', archive, payload])
            inputs = sorted(folder.iterdir())
            check('create-split-' + fmt, r.returncode == 0 and len(inputs) > 1)
            first = archive if archive.exists() else next(p for p in inputs if p.name.endswith('.001'))
            decoy = folder / (archive.name + f'.{len(inputs)+1:03}' if fmt == '7z' else archive.stem + f'.z{len(inputs):02}')
            decoy.write_bytes(b'unrelated similarly named file')
            extract('recycle-split-' + fmt, first, inputs, True)
            check('recycle-decoy-kept-' + fmt, decoy.read_bytes() == b'unrelated similarly named file')
            check('recycle-split-output-' + fmt, (cases / ('recycle-split-' + fmt + '-out') / payload.name).read_bytes() == payload.read_bytes())
        for version in ['rar3', 'rar5']:
            folder = cases / version; folder.mkdir(); inputs = []
            for number in [1, 2, 3]:
                name = f'{version}-vols.part{number}.rar'
                path = folder / name
                with urllib.request.urlopen('https://raw.githubusercontent.com/markokr/rarfile/master/test/files/' + name, timeout=25) as response:
                    path.write_bytes(response.read())
                inputs.append(path)
            decoy = folder / (version + '-vols.part4.rar'); decoy.write_bytes(b'unrelated extra volume')
            extract('recycle-' + version + '-volumes', inputs[0], inputs, True)
            check('recycle-' + version + '-decoy-kept', decoy.exists())
    finally:
        enable(False)
        restored = 0
        for line in trace().splitlines():
            marker = ' RECYCLED_ITEM '
            if marker not in line: continue
            original, recycled = line.split(marker, 1)[1].split('\t', 1)
            path = Path(original)
            if cases not in path.parents or path.exists(): continue
            r = run([restore, cases, original, recycled])
            if r.returncode != 0: raise AssertionError('Could not restore own recycled fixture')
            restored += 1
        check('recycled-fixtures-restored', restored > 0)
