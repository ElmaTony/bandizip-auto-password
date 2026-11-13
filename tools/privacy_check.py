"""Fail closed on personal paths, explicit private terms, credentials and PE debug data.
Set BZAP_PRIVATE_TERMS to a semicolon-separated local denylist; never commit it.
"""
from pathlib import Path
import os,re,struct,sys,zipfile
ROOT=Path(__file__).resolve().parents[1]
SKIP={'.git','build','dist','release','.toolchain','__pycache__','.venv'}
RUNTIME={'BandizipAutoPassword.exe','ark.x64.dll','README.md','LICENSE',
         'MbedTLS-LICENSE.txt','THIRD_PARTY_NOTICES.txt'}
FORBIDDEN={'.pdb','.log','.dmp','.jsonl'}
def check_bytes(name,data):
    problems=[]
    texts=[name,data.decode('utf8',errors='ignore'),data.decode('utf-16-le',errors='ignore'),data[1:].decode('utf-16-le',errors='ignore')]
    patterns=[r'(?i)[A-Z]:[\\/](?:Users|Documents|Project)[\\/]',r'gh[pousr]_[A-Za-z0-9]{30,}',r'github_pat_[A-Za-z0-9_]{30,}']
    terms=[x.casefold() for x in os.environ.get('BZAP_PRIVATE_TERMS','').split(';') if x]
    for text in texts:
        if any(re.search(pattern,text) for pattern in patterns) or any(term in text.casefold() for term in terms):problems.append(name);break
    if data[:2]==b'MZ':
        try:
            pe=struct.unpack_from('<I',data,60)[0];opt=pe+24;magic=struct.unpack_from('<H',data,opt)[0];directory=opt+(112 if magic==0x20b else 96)
            if any(struct.unpack_from('<II',data,directory+6*8)):problems.append(name+' (debug directory)')
        except (struct.error,IndexError):problems.append(name+' (invalid PE)')
    return problems
def files(root):
    for directory,dirs,names in os.walk(root):
        dirs[:]=[d for d in dirs if d not in SKIP]
        for name in names:yield Path(directory)/name
def check_artifacts(path):
    """Validate presence/completeness before scanning every artifact byte."""
    path=Path(path)
    failures=[];count=0
    if not path.exists():return [str(path)+' (missing artifact)'],0
    entries=[path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file())
    if not entries:return [str(path)+' (empty artifact directory)'],0
    if path.is_dir() and not any(p.suffix.lower()=='.zip' for p in entries):
        missing=RUNTIME-{p.name for p in entries if p.parent==path}
        if missing:failures.append(str(path)+' (missing runtime files: '+', '.join(sorted(missing))+')')
    for p in entries:
        try:
            if p.is_symlink():failures.append(p.name+' (symlink)');continue
            if p.suffix.lower()=='.zip':
                with zipfile.ZipFile(p) as z:
                    names={n for n in z.namelist() if not n.endswith('/')}
                    source=any(n.endswith('/src/proxy.cpp') or n=='src/proxy.cpp' for n in names)
                    required={'src/proxy.cpp','src/common.hpp','README.md','LICENSE'} if source else RUNTIME
                    prefix=next((n[:-len('src/proxy.cpp')] for n in names if n.endswith('src/proxy.cpp')),'') if source else ''
                    if not names or not all(prefix+n in names for n in required):
                        failures.append(p.name+' (incomplete archive)')
                    for name in names:
                        count+=1;failures+=check_bytes(name,z.read(name))
                        if Path(name).suffix.lower() in FORBIDDEN:failures.append(name)
            else:
                count+=1;failures+=check_bytes(p.name,p.read_bytes())
                if p.suffix.lower() in FORBIDDEN:failures.append(p.name)
        except (OSError,ValueError,zipfile.BadZipFile,RuntimeError) as error:
            failures.append(p.name+' (unreadable: '+type(error).__name__+')')
    if count==0:failures.append(str(path)+' (no artifact files scanned)')
    return failures,count

def main():
    failures=[];count=0
    for path in files(ROOT):count+=1;failures+=check_bytes(str(path.relative_to(ROOT)),path.read_bytes())
    for arg in sys.argv[1:] or [str(ROOT/'release')]:
        found,scanned=check_artifacts(arg);failures+=found;count+=scanned
    if failures:print('Privacy check FAILED: '+', '.join(sorted(set(failures))));return 1
    print(f'Privacy check passed: {count} files.');return 0
if __name__=='__main__':raise SystemExit(main())
