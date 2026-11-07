"""Windows integration tests against a disposable Bandizip copy and dummy HKCU.
Requires Python 3.10+, pefile and cryptography. No real passwords are read.
Run after build.ps1 -Tests. --zig points to the pinned Zig 0.13.0 compiler.
"""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, shutil, struct, subprocess, time, uuid, winreg, zipfile, zlib, urllib.request
import pefile
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, modes

ROOT=Path(__file__).resolve().parents[1]
PASSWORDS=['wrong-first','wrong-second','password','fixture-secret','中文测试🔑']
CONTENT=b'Bandizip Auto Password integration fixture.\n'
ORIGINAL='868a4b870f43024688d4e9c74d9c4e42bc7f4e439972a93059ee95f4a2dbb135'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def swap(data):return b''.join(data[i:i+4][::-1] for i in range(0,len(data),4))
def store_blob(passwords):
    key=b'the truth is over there'
    plain=('[test]\n'+''.join(p+'\tDummy entry\n' for p in passwords)).encode('utf8')
    plain+=b'\0'*((-len(plain))%8)
    enc=Cipher(Blowfish(key),modes.ECB()).encryptor()
    return '1'+format(zlib.crc32(key),'08x')+swap(enc.update(swap(plain))+enc.finalize()).hex()

def add_isolation_import(path):
    pe=pefile.PE(str(path));image=bytearray(path.read_bytes());align=lambda n,a:(n+a-1)//a*a
    last=pe.sections[-1];rva=align(last.VirtualAddress+max(last.Misc_VirtualSize,last.SizeOfRawData),pe.OPTIONAL_HEADER.SectionAlignment)
    offset=align(len(image),pe.OPTIONAL_HEADER.FileAlignment)
    desc=b''.join(image[d.struct.get_file_offset():d.struct.get_file_offset()+20] for d in pe.DIRECTORY_ENTRY_IMPORT)
    name=b'isolate.dll\0';symbol=b'\0\0ResearchNoop\0';nameoff=len(desc)+40
    symoff=align(nameoff+len(name),2);thunkoff=align(symoff+len(symbol),8)
    payload=bytearray(desc+struct.pack('<IIIII',rva+thunkoff,0,0,rva+nameoff,rva+thunkoff)+b'\0'*20)
    payload+=name;payload+=b'\0'*(symoff-len(payload));payload+=symbol;payload+=b'\0'*(thunkoff-len(payload));payload+=struct.pack('<QQ',rva+symoff,0)
    rawsize=align(len(payload),pe.OPTIONAL_HEADER.FileAlignment);sectionoff=last.get_file_offset()+40
    assert sectionoff+40<=pe.sections[0].PointerToRawData
    image[sectionoff:sectionoff+40]=struct.pack('<8sIIIIIIHHI',b'.bztest\0',len(payload),rva,rawsize,offset,0,0,0,0,0xc0000040)
    struct.pack_into('<H',image,pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'),pe.FILE_HEADER.NumberOfSections+1)
    struct.pack_into('<II',image,pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].get_file_offset(),rva,len(desc)+40)
    struct.pack_into('<I',image,pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'),align(rva+len(payload),pe.OPTIONAL_HEADER.SectionAlignment))
    image+=b'\0'*(offset-len(image));image+=payload;image+=b'\0'*(rawsize-len(payload));pe.close();path.write_bytes(image)

TABLE=[]
for n in range(256):
    c=n
    for _ in range(8):c=(c>>1)^(0xedb88320 if c&1 else 0)
    TABLE.append(c)
class ZipCrypto:
    def __init__(self,password):
        self.a,self.b,self.c=0x12345678,0x23456789,0x34567890
        for v in password.encode('utf8'):self.update(v)
    def update(self,ch):
        self.a=((self.a>>8)^TABLE[(self.a^ch)&255])&0xffffffff
        self.b=((self.b+(self.a&255))*134775813+1)&0xffffffff
        self.c=((self.c>>8)^TABLE[(self.c^(self.b>>24))&255])&0xffffffff
    def mask(self):
        t=self.c|2;return ((t*(t^1))>>8)&255
    def encrypt(self,data):
        out=bytearray()
        for v in data:out.append(v^self.mask());self.update(v)
        return out
    def decrypt(self,data):
        out=bytearray()
        for v in data:v^=self.mask();out.append(v);self.update(v)
        return out

def encrypted_zip(path,password,collision=None):
    crc=zlib.crc32(CONTENT)
    for _ in range(100000):
        header=os.urandom(11)+bytes([crc>>24]);enc=ZipCrypto(password).encrypt(header+CONTENT)
        if collision is None:break
        decoded=ZipCrypto(collision).decrypt(enc)
        if decoded[11]==crc>>24 and zlib.crc32(decoded[12:])!=crc:break
    else:raise AssertionError('could not create deterministic-condition collision fixture')
    name=b'proof.txt';size=len(enc);flags=0x801
    local=struct.pack('<IHHHHHIIIHH',0x04034b50,20,flags,0,0,0,crc,size,len(CONTENT),len(name),0)+name+enc
    central=struct.pack('<IHHHHHHIIIHHHHHII',0x02014b50,20,20,flags,0,0,0,crc,size,len(CONTENT),len(name),0,0,0,0,0,0)+name
    path.write_bytes(local+central+struct.pack('<IHHHHIIH',0x06054b50,0,0,1,1,len(central),len(local),0))
    with zipfile.ZipFile(path) as z:assert z.read('proof.txt',pwd=password.encode())==CONTENT

def delete_key(parent,name):
    try:
        with winreg.OpenKey(parent,name,0,winreg.KEY_ALL_ACCESS) as k:
            while winreg.QueryInfoKey(k)[0]:delete_key(k,winreg.EnumKey(k,0))
        winreg.DeleteKey(parent,name)
    except FileNotFoundError:pass

def merge_zip(destination,archives):
    locals_,centrals=[],[];offset=0
    for archive in archives:
        central_size,central_offset=struct.unpack_from('<II',archive,len(archive)-10)
        central=bytearray(archive[central_offset:central_offset+central_size]);struct.pack_into('<I',central,42,offset)
        locals_.append(archive[:central_offset]);centrals.append(central);offset+=central_offset
    central=b''.join(centrals);count=len(archives)
    destination.write_bytes(b''.join(locals_)+central+struct.pack('<IHHHHIIH',0x06054b50,0,0,count,count,len(central),offset,0))

def close_test_process(pid,executable):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_uint];kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_uint)]
    kernel.TerminateProcess.argtypes=[ctypes.c_void_p,ctypes.c_uint];kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.OpenProcess(0x1001,False,pid)
    if handle:
        buffer=ctypes.create_unicode_buffer(32768);size=ctypes.c_uint(32768)
        if kernel.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size)) and Path(buffer.value).resolve()==executable.resolve():kernel.TerminateProcess(handle,0)
        kernel.CloseHandle(handle)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--zig',required=True);ap.add_argument('--bandizip',default=r'C:\Program Files\Bandizip');ap.add_argument('--work',default=str(ROOT/'build/integration'));ap.add_argument('--package',default=str(ROOT/'dist'));args=ap.parse_args()
    source=Path(args.bandizip);work=Path(args.work)/uuid.uuid4().hex;work.mkdir(parents=True);app=work/'app';app.mkdir();fixtures=work/'fixtures';fixtures.mkdir();data=work/'data';data.mkdir()
    results=[];children=[];key='Software\\BandizipAutoPasswordTests\\integration-'+uuid.uuid4().hex
    env=dict(os.environ,BANDIZIP_RESEARCH_KEY=key,BZAP_DATA_DIR=str(data),BZAP_TRACE=str(work/'trace.txt'),BZAP_NO_UI='1')
    original_hashes={n:sha(source/n) for n in ['Bandizip.exe','ark.x64.dll','bdzshl.x64.dll','data/bzshell.x64.dll']}
    assert original_hashes['ark.x64.dll']==ORIGINAL,'Unsupported source build'
    def check(name,ok,**details):
        results.append(dict(test=name,passed=bool(ok),**details));print(json.dumps(results[-1],ensure_ascii=True),flush=True)
        if not ok:raise AssertionError(name)
    def run(command,timeout=25,**kwargs):return subprocess.run(list(map(str,command)),env=env,capture_output=True,timeout=timeout,**kwargs)
    def manage(action):
        result=work/'install-result.json';r=run([Path(args.package)/'BandizipAutoPassword.exe',action,'--directory',app,'--quiet','--result',result]);return r,json.loads(result.read_text('utf8'))
    def history():
        p=data/'history.jsonl';return [json.loads(l) for l in p.read_text('utf8').splitlines()] if p.exists() else []
    def trace():return (work/'trace.txt').read_text('utf8') if (work/'trace.txt').exists() else ''
    def extract(label,archive,success,notify=False):
        output=work/label;before=len(history());e=dict(env)
        if notify:e.pop('BZAP_NO_UI',None);e['BZAP_TEST_AUTOCLOSE_MS']='200'
        p=subprocess.Popen([str(app/'Bandizip.exe'),'x','-y','-o:'+str(output),str(fixtures/archive)],env=e,cwd=app);children.append(p)
        try:code=p.wait(timeout=25)
        except subprocess.TimeoutExpired:p.terminate();p.wait(5);check(label+'-no-hang',False)
        file=output/'proof.txt';matches=file.exists() and file.read_bytes()==CONTENT
        records=history()[before:];check(label,(matches if success else not file.exists()) and code<0x80000000,exit=code,records=records)
        if not success:check(label+'-reported',any(r['outcome'].startswith('password') and r['archive'].endswith(archive) for r in records))
        if not success:check(label+'-not-success',not any(r['outcome']=='success' for r in records))
        if not success:check(label+'-archive-preserved',(fixtures/archive).exists())
        return records
    try:
        for n in ['Bandizip.exe','bz.exe','ark.x64.dll','ark.x64.lgpl.dll','bdzshl.x64.dll','config.ini','VersionNo.ini']:
            if (source/n).exists():shutil.copy2(source/n,app/n)
        for n in ['data','langs','icons','shellicons']:
            if (source/n).exists():shutil.copytree(source/n,app/n)
        r=run([args.zig,'c++','-target','x86_64-windows-gnu','-march=x86_64','-O2','-static','-shared',ROOT/'tests/isolate.cpp','-ladvapi32','-o',app/'isolate.dll'],timeout=120);assert r.returncode==0,r.stderr.decode(errors='replace')
        add_isolation_import(app/'Bandizip.exe')
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,key+r'\Software\Bandizip',0,winreg.KEY_ALL_ACCESS) as k:
            for n,v in [('bIsFirst2',0),('doNotCloseExtractDlg',0),('openFolderWhenComplete',0),('bSaveRecentFileList',0),('bUseElegantUI',0)]:winreg.SetValueEx(k,n,0,winreg.REG_DWORD,v)
            winreg.SetValueEx(k,'language',0,winreg.REG_SZ,'simpchinese')
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,key+r'\Software\Bandizip\passman',0,winreg.KEY_ALL_ACCESS) as k:winreg.SetValueEx(k,'data',0,winreg.REG_SZ,store_blob(PASSWORDS+PASSWORDS[:1]))
        r,install=manage('--install');check('install',r.returncode==0 and install['ok'],result=install)
        check('backup-exact',sha(app/'ark.bzap-original.x64.dll')==ORIGINAL)
        r,install=manage('--install');check('reinstall-idempotent',r.returncode==0 and install['ok'])
        forged=work/'forged-package';forged.mkdir();shutil.copy2(Path(args.package)/'BandizipAutoPassword.exe',forged/'BandizipAutoPassword.exe');shutil.copy2(Path(args.package)/'ark.x64.dll',forged/'ark.x64.dll')
        with (forged/'ark.x64.dll').open('ab') as f:f.write(b'mismatched-package')
        before=sha(app/'ark.x64.dll');result=work/'forged-result.json'
        r=run([forged/'BandizipAutoPassword.exe','--install','--quiet','--directory',app,'--result',result])
        check('mismatched-package-refused',not json.loads(result.read_text('utf8'))['ok'] and sha(app/'ark.x64.dll')==before)
        (app/'AutoPassword/installation.ini').unlink();r,install=manage('--install')
        check('missing-manifest-recovered',install['ok'] and (app/'AutoPassword/installation.ini').exists())
        r=run([Path(args.package)/'BandizipAutoPassword.exe','--status','--directory',app,'--result',work/'absent-directory/result.json'])
        check('result-write-failure-reported',r.returncode!=0)
        (fixtures/'proof.txt').write_bytes(CONTENT)
        with zipfile.ZipFile(fixtures/'plain.zip','w') as z:z.writestr('proof.txt',CONTENT)
        encrypted_zip(fixtures/'saved.zip','fixture-secret');encrypted_zip(fixtures/'unknown.zip','not-saved-'+uuid.uuid4().hex)
        encrypted_zip(fixtures/'collision.zip','fixture-secret',collision=PASSWORDS[0])
        for name,password in [('header.7z','fixture-secret'),('unknown-header.7z','not-saved-'+uuid.uuid4().hex),('unicode.7z',PASSWORDS[-1])]:
            r=run([source/'bz.exe','c','-fmt:7z','-p:'+password,fixtures/name,fixtures/'proof.txt']);check('create-'+name,r.returncode==0)
        extract('plain','plain.zip',True);extract('saved-later','saved.zip',True);extract('all-wrong','unknown.zip',False)
        extract('header-saved','header.7z',True);extract('header-all-wrong','unknown-header.7z',False);extract('unicode-password','unicode.7z',True)
        before=len(trace());extract('zip-header-collision','collision.zip',True);check('collision-full-validation','RETRY_AFTER_PASSWORD_OR_CRC_ERROR' in trace()[before:])
        out=work/'batch';before=len(history());files=['saved.zip','unknown.zip','unknown-header.7z','header.7z']
        r=run([app/'Bandizip.exe','bx','-y','-target:name','-o:'+str(out),*[fixtures/n for n in files]])
        outputs={n:(out/Path(n).stem/'proof.txt').exists() for n in files};check('batch-continues',outputs==dict(zip(files,[True,False,False,True])),outputs=outputs,records=history()[before:])
        before=len(trace());extract('failure-notification','unknown.zip',False,notify=True);check('native-failure-notification','NOTIFICATION_CREATED' in trace()[before:])
        # Real unchanged classic and Windows 11 COM menu implementations.
        driver=work/'native_menu_driver.exe'
        r=run([args.zig,'c++','-target','x86_64-windows-gnu','-march=x86_64','-O2','-static','-municode',ROOT/'tests/native_menu_driver.cpp','-ladvapi32','-lshell32','-lole32','-luuid','-luser32','-o',driver],timeout=120)
        check('build-native-driver',r.returncode==0,stderr=r.stderr.decode(errors='replace')[-1000:])
        # The Win11 extension identifies its COM surrogate by the host basename.
        modern=app/'DllHost.exe';shutil.copy2(driver,modern)
        for mode,host in [('classic',driver),('modern',modern)]:
            folder=work/('menu-'+mode);folder.mkdir();archive=folder/'saved.zip';shutil.copy2(fixtures/'saved.zip',archive)
            r=run([host,app,archive,key,mode,'智能解压到此处'])
            outputs=list(folder.rglob('proof.txt'))
            check('native-'+mode,r.returncode==0 and any(p.read_bytes()==CONTENT for p in outputs),exit=r.returncode,native_trace=r.stdout.decode('utf8',errors='replace')[-2200:])
        before=len(trace());r=run([driver,app,fixtures/'header.7z',key,'open']);time.sleep(.7);opened=trace()[before:]
        open_pids={int(line.split(' ',1)[0]) for line in opened.splitlines() if 'SUPPORTED_BUILD_ENABLED' in line}
        for pid in open_pids:close_test_process(pid,app/'Bandizip.exe')
        check('shell-open-header-archive',r.returncode==0 and 'OPEN_SUCCEEDED' in opened and 'TRY_SAVED index=4' in opened)
        # Compare RAR results with the original console engine and a known public
        # fixture password, never with any password from the user's real store.
        for name in ['rar5-psw.rar','rar5-hpsw.rar','rar3-comment-psw.rar']:
            path=fixtures/name;url='https://raw.githubusercontent.com/markokr/rarfile/master/test/files/'+name
            with urllib.request.urlopen(url,timeout=20) as response:path.write_bytes(response.read())
            baseline=work/('baseline-'+name);out=work/('rar-'+name)
            a=run([source/'bz.exe','x','-y','-p:password','-o:'+str(baseline),path]);b=run([app/'Bandizip.exe','x','-y','-o:'+str(out),path])
            hashes=lambda folder:{str(p.relative_to(folder)):sha(p) for p in folder.rglob('*') if p.is_file()}
            check(name,a.returncode==0 and b.returncode<0x80000000 and bool(hashes(baseline)) and hashes(out)==hashes(baseline),fixture_sha256=sha(path),url=url)
        # Extracting one selected file must not require the other file's password.
        raw=(fixtures/'saved.zip').read_bytes();other=(fixtures/'unknown.zip').read_bytes().replace(b'proof.txt',b'other.txt')
        mixed=fixtures/'mixed.zip';merge_zip(mixed,[raw,other])
        out=work/'selected-only';r=run([app/'Bandizip.exe','x','-y','-o:'+str(out),mixed,'proof.txt'])
        check('selected-file-only',r.returncode<0x80000000 and (out/'proof.txt').read_bytes()==CONTENT and not (out/'other.txt').exists())
        encrypted_zip(fixtures/'second-known.zip','password');other=(fixtures/'second-known.zip').read_bytes().replace(b'proof.txt',b'other.txt');mixed=fixtures/'mixed-known.zip';merge_zip(mixed,[raw,other])
        out=work/'multiple-passwords';r=run([app/'Bandizip.exe','x','-y','-o:'+str(out),mixed])
        check('different-passwords-in-one-zip',r.returncode<0x80000000 and all((out/n).exists() and (out/n).read_bytes()==CONTENT for n in ['proof.txt','other.txt']))
        # A valid password plus corrupted data must not produce a confident
        # "wrong password" diagnosis or write any unverified output.
        bad=bytearray(raw);bad[40+len(CONTENT)]^=1;(fixtures/'damaged.zip').write_bytes(bad)
        records=extract('damaged-data','damaged.zip',False)
        check('damaged-data-qualified',any(r['outcome']=='password_or_data_error' for r in records))
        r,removed=manage('--uninstall');check('uninstall',r.returncode==0 and removed['ok']);check('original-restored',sha(app/'ark.x64.dll')==ORIGINAL)
        # A damaged original is never replaced, and missing-engine recovery uses
        # only the previously verified backup.
        with (app/'ark.x64.dll').open('ab') as f:f.write(b'test overlay')
        r,result=manage('--install');check('unsupported-engine-refused',not result['ok'])
        shutil.copy2(source/'ark.x64.dll',app/'ark.x64.dll');r,result=manage('--install');check('reinstall-after-restore',result['ok'])
        missing=app/'ark.interrupted-install-test.dll';(app/'ark.x64.dll').rename(missing)
        r,result=manage('--install');check('missing-engine-recovery',result['ok'])
        r,result=manage('--uninstall');check('recovered-uninstall',result['ok'] and sha(app/'ark.x64.dll')==ORIGINAL)
        r,result=manage('--install');assert result['ok']
        backup=app/'ark.bzap-original.x64.dll';backup.write_bytes(backup.read_bytes()+b'bad-backup-test');current=sha(app/'ark.x64.dll')
        r,result=manage('--uninstall');check('damaged-backup-refused',not result['ok'] and sha(app/'ark.x64.dll')==current)
        shutil.copy2(source/'ark.x64.dll',backup)
        shutil.copy2(source/'ark.x64.dll',app/'ark.x64.dll')
        with (app/'ark.x64.dll').open('ab') as f:f.write(b'new-version-simulation')
        newer=sha(app/'ark.x64.dll');r,result=manage('--uninstall');check('uninstall-preserves-new-engine',result['ok'] and sha(app/'ark.x64.dll')==newer)
        check('live-files-unchanged',original_hashes=={n:sha(source/n) for n in original_hashes})
        logged=(data/'history.jsonl').read_text('utf8')
        allowed={'time','pid','archive','outcome','error','attempts','saved_password_count','completed_files','opening'}
        check('no-passwords-in-history',not any(p in logged for p in PASSWORDS if p!='password') and all(set(r)<=allowed for r in history()))
    finally:
        for p in children:
            if p.poll() is None:p.terminate();p.wait(5)
        delete_key(winreg.HKEY_CURRENT_USER,key)
        (work/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),'utf8')
        (ROOT/'build/integration-latest.json').write_text(json.dumps(dict(work=str(work),results=results),ensure_ascii=False,indent=2),'utf8')
        print('RESULTS '+str(work/'results.json'),flush=True)
    return 0
if __name__=='__main__':raise SystemExit(main())
