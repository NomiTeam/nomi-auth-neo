param([Parameter(Mandatory = $true)][string]$Binary)

$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$dumpbin = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
if (-not $dumpbin) { throw 'MSVC dumpbin was not found' }

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$imports = & $dumpbin /DEPENDENTS $binaryPath
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect executable imports' }
$imports
if (($imports -join "`n") -match '(?i)\b(vcruntime\S*|msvcp\S*|msvcr\S*|concrt\S*|ucrtbase\S*|api-ms-win-crt\S*|libgcc\S*|libstdc\S*|libwinpthread\S*|sqlite3|libssl\S*|libcrypto\S*)\.dll\b') {
    throw 'The executable imports an additional runtime DLL'
}
