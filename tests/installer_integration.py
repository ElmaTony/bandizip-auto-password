"""Installer checks confined to the integration runner's disposable app copy."""
import ctypes
import re


def run_installer_tests(app, manage, check, sha, original):
    _, status = manage('--status')
    version = status['package_version']
    check('installed-version-current', status['installed'] and
          status['installed_version'] == version and not status['update_available'])
    engine = app / 'ark.x64.dll'
    manifest = app / 'AutoPassword/installation.ini'
    current = engine.read_bytes()
    engine.write_bytes(current + b'synthetic-old-package')
    text = manifest.read_text('utf8')
    text = re.sub(r'^Version=.*$', 'Version=0.9.0', text, flags=re.M)
    text = re.sub(r'^ProxySHA256=.*$', 'ProxySHA256=' + sha(engine), text, flags=re.M)
    manifest.write_text(text, encoding='utf8')
    _, status = manage('--status')
    check('older-version-update-offered', status['installed'] and
          status['installed_version'] == '0.9.0' and status['update_available'])

    folder = app / 'AutoPassword'
    obsolete = [folder / name for name in
                ['retired-100.dll', 'retired-proxy-200.dll', 'uncommitted-300.dll']]
    locked = folder / 'retired-400.dll'
    unrelated = folder / 'retired-keep.dll'
    for path in [*obsolete, locked, unrelated]:
        path.write_bytes(b'synthetic retired component')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint,
                                  ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.CreateFileW(str(locked), 0x80000000, 1, None, 3, 0x80, None)
    assert handle != ctypes.c_void_p(-1).value
    try:
        _, result = manage('--install')
        check('update-restores-current-package', result['ok'] and engine.read_bytes() == current)
        check('retired-unlocked-components-cleaned', all(not p.exists() for p in obsolete))
        check('retired-locked-and-unrelated-preserved', locked.exists() and unrelated.exists())
        check('cleanup-keeps-original-backup', sha(app / 'ark.bzap-original.x64.dll') == original)
    finally:
        kernel.CloseHandle(handle)
    _, result = manage('--install')
    check('retired-component-cleaned-after-release', result['ok'] and not locked.exists())
    _, status = manage('--status')
    check('updated-version-status', status['installed_version'] == version and not status['update_available'])


def check_uninstalled(app, manage, check):
    _, status = manage('--status')
    check('uninstalled-version-status', not status['installed'] and
          not status['installed_version'] and not status['update_available'])
    check('uninstall-cleans-retired-components',
          sorted(p.name for p in (app / 'AutoPassword').glob('*.dll')) == ['retired-keep.dll'])
