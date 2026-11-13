from pathlib import Path
import sys,tempfile,unittest,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from privacy_check import check_artifacts,RUNTIME

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

if __name__=='__main__':unittest.main()
