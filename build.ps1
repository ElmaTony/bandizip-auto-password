param([string]$ZigPath = $env:ZIG_EXE, [switch]$Tests, [string]$OutputDirectory='dist')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $ZigPath) {
    $zigCommand = Get-Command zig -ErrorAction SilentlyContinue
    if ($zigCommand) { $ZigPath = $zigCommand.Source }
    else { $ZigPath = Join-Path $root 'tools\.toolchain\zig-windows-x86_64-0.13.0\zig.exe' }
}
if (-not (Test-Path -LiteralPath $ZigPath)) { throw '未找到 Zig。请运行 tools\bootstrap-zig.ps1，或用 -ZigPath 指定 Zig 0.13.0。' }
$ZigPath = (Resolve-Path -LiteralPath $ZigPath).Path
$version = (& $ZigPath version).Trim()
if ($version -ne '0.13.0') { throw "当前构建固定使用 Zig 0.13.0，找到的是 $version。" }
$build = Join-Path $root 'build'
$dist = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Path $build,$dist -Force | Out-Null
Push-Location $root
try {
    & $ZigPath cc -target x86_64-windows-gnu -march=x86_64 -O2 -c 'third_party/mbedtls/library/blowfish.c' '-Ithird_party/mbedtls/include' -o 'build/blowfish.o'
    if ($LASTEXITCODE -ne 0) { throw 'Blowfish 组件构建失败。' }
    $common = @('src/common.cpp','src/password_store.cpp','src/reporting.cpp','build/blowfish.o')
    $flags = @('-target','x86_64-windows-gnu','-march=x86_64','-std=c++17','-O2','-g0','-s','-DNDEBUG','-static','-Ibuild','-Ithird_party/mbedtls/include','-DUNICODE','-D_UNICODE','-U_WIN32_WINNT','-D_WIN32_WINNT=0x0A00','-DWINVER=0x0A00')
    $libraries = @('-ladvapi32','-luser32','-lgdi32','-lcomctl32','-lshell32','-lole32','-luuid','-lversion','-lbcrypt')
    & $ZigPath c++ @flags -shared 'src/proxy.cpp' @common @libraries -o (Join-Path $dist 'ark.x64.dll')
    if ($LASTEXITCODE -ne 0) { throw '扩展 DLL 构建失败。' }
    $proxyHash = (Get-FileHash -LiteralPath (Join-Path $dist 'ark.x64.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $build 'package_identity.hpp'), ('inline constexpr char PackageSha256[]="' + $proxyHash + '";'), [Text.UTF8Encoding]::new($false))
    Push-Location (Join-Path $root 'src')
    try { & $ZigPath rc /fo '../build/manager.res' 'manager.rc' }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw '管理器资源构建失败。' }
    & $ZigPath c++ @flags -municode '-Wl,/subsystem:windows' 'src/manager.cpp' 'src/installer.cpp' @common 'build/manager.res' @libraries -o (Join-Path $dist 'BandizipAutoPassword.exe')
    if ($LASTEXITCODE -ne 0) { throw '管理器构建失败。' }
    if ($Tests) {
        & $ZigPath c++ @flags -municode '-Isrc' 'tests/unit_tests.cpp' @common 'build/manager.res' @libraries -o 'build/unit_tests.exe'
        if ($LASTEXITCODE -ne 0) { throw '单元测试构建失败。' }
        & (Join-Path $root 'build/unit_tests.exe')
        if ($LASTEXITCODE -ne 0) { throw '单元测试失败。' }
    }
    foreach ($name in @('README.md','THIRD_PARTY_NOTICES.txt','LICENSE')) { if (Test-Path -LiteralPath (Join-Path $root $name)) { Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $dist $name) -Force } }
    Copy-Item -LiteralPath (Join-Path $root 'third_party/mbedtls/LICENSE') -Destination (Join-Path $dist 'MbedTLS-LICENSE.txt') -Force
    Write-Output "构建完成：$dist"
} finally { Pop-Location }
