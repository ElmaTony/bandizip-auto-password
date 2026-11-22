from pathlib import Path
import hashlib
import os
import sys,tempfile,unittest,warnings,zipfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from privacy_check import check_artifacts, RUNTIME, RUNTIME_DOCS, SOURCE_BUILD

class ArtifactChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='bzap-privacy-')
        self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def test_missing(self):self.assertTrue(check_artifacts(self.root/'missing')[0])
    def test_empty_directory(self):self.assertTrue(check_artifacts(self.root)[0])
    def test_incomplete_runtime(self):
        (self.root/'README.md').write_text('example','utf8')
        self.assertTrue(check_artifacts(self.root)[0])
    def test_complete_runtime(self):
        for name in RUNTIME:(self.root/name).write_bytes(b'synthetic test data')
        errors,count=check_artifacts(self.root)
        self.assertEqual(errors,[]);self.assertEqual(count,len(RUNTIME))
    def test_empty_zip(self):
        path=self.root/'empty.zip'
        with zipfile.ZipFile(path,'w'):pass
        self.assertTrue(check_artifacts(path)[0])
    def test_corrupt_zip(self):
        path=self.root/'bad.zip';path.write_bytes(b'not a ZIP')
        self.assertTrue(check_artifacts(path)[0])
    def test_uppercase_zip_scanned(self):
        path=self.root/'runtime.ZIP'
        with zipfile.ZipFile(path,'w') as z:
            for name in RUNTIME:z.writestr(name,b'synthetic test data')
            z.writestr('history.JSONL',b'private record')
        self.assertIn('history.JSONL',check_artifacts(path)[0])
    def test_valid_source_archive(self):
        path=self.root/'source.zip'
        with zipfile.ZipFile(path,'w') as z:
            for name in ['src/proxy.cpp','src/common.hpp','README.md','LICENSE']:
                z.writestr('source/'+name,b'synthetic source')
        self.assertEqual(check_artifacts(path)[0],[])

    def test_duplicate_archive_entries(self):
        path = self.root / 'runtime.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as archive:
                for name in RUNTIME:
                    archive.writestr(name, b'first entry')
                archive.writestr('README.md', b'second entry')
        self.assertTrue(check_artifacts(path)[0])

    def test_empty_required_file(self):
        for name in RUNTIME:
            (self.root / name).write_bytes(b'' if name == 'ark.x64.dll' else b'fixture')
        self.assertTrue(check_artifacts(self.root)[0])

    def test_missing_release_artifacts(self):
        with zipfile.ZipFile(self.root / 'BandizipAutoPassword-1.0.0-windows-x64.zip', 'w') as archive:
            for name in RUNTIME:
                archive.writestr(name, b'fixture')
        self.assertTrue(check_artifacts(self.root)[0])

    def test_release_checksums_match_both_packages(self):
        sums = []
        for kind, names in [('windows-x64', RUNTIME | RUNTIME_DOCS), ('source', SOURCE_BUILD)]:
            path = self.root / f'BandizipAutoPassword-1.0.0-{kind}.zip'
            with zipfile.ZipFile(path, 'w') as package:
                prefix = 'BandizipAutoPassword-source/' if kind == 'source' else ''
                for name in sorted(names):
                    package.writestr(prefix + name, b'fixture')
            sums.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name)
        manifest = self.root / 'SHA256SUMS.txt'
        manifest.write_text('\n'.join(sums) + '\n', encoding='ascii')
        self.assertEqual(check_artifacts(self.root)[0], [])
        manifest.write_text('\n'.join([sums[0], sums[0]]), encoding='ascii')
        self.assertTrue(check_artifacts(self.root)[0])

    def test_archive_comment_is_scanned(self):
        path = self.root / 'runtime.zip'
        with zipfile.ZipFile(path, 'w') as package:
            for name in RUNTIME:
                package.writestr(name, b'fixture')
            package.comment = b'synthetic-test-marker'
        with patch.dict(os.environ, BZAP_PRIVATE_TERMS='synthetic-test-marker'):
            self.assertTrue(check_artifacts(path)[0])

if __name__=='__main__':unittest.main()
