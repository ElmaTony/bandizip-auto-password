$ErrorActionPreference='Stop'
$directory=Join-Path $PSScriptRoot '.toolchain'
$archive=Join-Path $directory 'zig-windows-x86_64-0.13.0.zip'
$expected='d859994725ef9402381e557c60bb57497215682e355204d754ee3df75ee3c158'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
if(-not(Test-Path -LiteralPath $archive)){
    Invoke-WebRequest -Uri 'https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip' -OutFile $archive
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Zig 下载校验失败，未运行或解压。'}
$compiler=Join-Path $directory 'zig-windows-x86_64-0.13.0\zig.exe'
if(-not(Test-Path -LiteralPath $compiler)){Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force}
Write-Output "Zig 0.13.0 已准备好：$compiler"
