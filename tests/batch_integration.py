"""Multiple-file batch regression using the isolated, licensed Bandizip host."""
import hashlib
import os


def run_batch_tests(app, source, work, data, run, check, history, trace):
    cases = work / 'batch-regression'; cases.mkdir()
    payload = cases / 'payload'; payload.mkdir()
    expected = {}
    for index in range(40):
        name = f'file-{index:03}.bin'
        content = os.urandom(128 * 1024)
        (payload / name).write_bytes(content)
        expected[name] = hashlib.sha256(content).hexdigest()
    archives = []
    for index in range(5):
        path = cases / f'archive-{index}.zip'
        result = run([source / 'bz.exe', 'c', '-fmt:zip', '-l:0', '-p:fixture-secret', path, *payload.iterdir()], timeout=60)
        assert result.returncode == 0
        archives.append(path)
    settings = data / 'settings.ini'
    for preflight in [False, True]:
        settings.write_text('[General]\nFullPreflight=' + str(int(preflight)) + '\nNotifyFailures=0\n', 'utf8')
        target = cases / ('preflight' if preflight else 'single-pass')
        before = len(history()); start = len(trace())
        result = run([app / 'Bandizip.exe', 'bx', '-y', '-aoa', '-target:name', '-o:' + str(target), *archives], timeout=90)
        records = history()[before:]
        valid = result.returncode < 0x80000000
        for archive in archives:
            actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (target / archive.stem).glob('*.bin')}
            valid = valid and actual == expected
        check('batch-200-files-' + ('preflight' if preflight else 'single-pass'), valid and
              len(records) == 5 and all(r['outcome'] == 'success' and r['completed_files'] == 40 for r in records))
        if not preflight:
            check('batch-no-extra-decompression', 'VERIFY_BEFORE_EXTRACT' not in trace()[start:])
    settings.write_text('[General]\nFullPreflight=0\n', 'utf8')
