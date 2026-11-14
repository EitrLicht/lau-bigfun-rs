# Fails unless the Windows executable at -Path links the C runtime statically: dumpbin must list
# its DLL dependencies, and none of them may be a Visual C++ or Universal C runtime DLL.
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)
$ErrorActionPreference = 'Stop'

$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$dumpbin = Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" | Select-Object -First 1
if (-not $dumpbin) { throw 'dumpbin.exe not found' }

$deps = & $dumpbin.FullName /dependents $Path
if ($LASTEXITCODE -ne 0) { throw "dumpbin failed with exit code $LASTEXITCODE" }
$deps
if (-not ($deps -match 'kernel32\.dll')) { throw 'dumpbin listed no dependencies' }
if ($deps -match 'vcruntime|msvcp|ucrtbase|api-ms-win-crt') { throw "$Path depends on C runtime DLLs" }
