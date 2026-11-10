param(
    [switch]$DownloadCore,
    [string]$PythonPath
)
$ErrorActionPreference = 'Stop'
$NativeDir = $PSScriptRoot

function Resolve-PythonExecutable {
    param([string]$ExplicitPath)
    $ExecCode = "import sys, base64; print(base64.b64encode(sys.executable.encode('utf-8')).decode('ascii')) if sys.version_info >= (3, 10) else sys.exit(2)"
    if ($ExplicitPath) {
        $Full = [IO.Path]::GetFullPath($ExplicitPath.Trim())
        if (-not (Test-Path -LiteralPath $Full)) { throw "Python executable not found: $Full" }
        $PrevPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $B64 = & $Full -c $ExecCode 2>$null
        $Code = $LASTEXITCODE
        $ErrorActionPreference = $PrevPref
        if ($Code -ne 0 -or -not $B64) { throw "Python 3.10+ is required at: $Full" }
        return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($B64 | Select-Object -First 1).Trim()))
    }

    $Candidates = @()
    foreach ($Name in @('python', 'python3')) {
        $Cmd = Get-Command $Name -ErrorAction SilentlyContinue
        if ($Cmd) { $Candidates += ,@($Cmd.Source, @()) }
    }
    $PyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($PyLauncher) { $Candidates += ,@($PyLauncher.Source, @('-3')) }

    foreach ($Item in $Candidates) {
        $Exe = $Item[0]
        $PrefixArgs = $Item[1]
        $PrevPref = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $B64 = & $Exe @PrefixArgs -c $ExecCode 2>$null
            $Code = $LASTEXITCODE
            if ($Code -eq 0 -and $B64) {
                $Resolved = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($B64 | Select-Object -First 1).Trim()))
                if ($Resolved -and (Test-Path -LiteralPath $Resolved)) {
                    return [IO.Path]::GetFullPath($Resolved)
                }
            }
        } catch {
            continue
        } finally {
            $ErrorActionPreference = $PrevPref
        }
    }
    throw 'Python 3.10+ not found. Install Python 3.10+ (python.org) or pass -PythonPath C:\path\python.exe.'
}

$PythonPath = Resolve-PythonExecutable -ExplicitPath $PythonPath

if ($DownloadCore) {
    & $PythonPath (Join-Path $NativeDir 'download_core.py')
    if ($LASTEXITCODE -ne 0) { throw 'Core download failed. Native host was not registered.' }
}

$Core = Join-Path $NativeDir 'bin\sing-box.exe'
if (-not (Test-Path -LiteralPath $Core)) {
    throw 'sing-box.exe missing. Re-run with -DownloadCore or copy official sing-box.exe to native\bin.'
}
& $Core version
if ($LASTEXITCODE -ne 0) { throw 'sing-box failed to start.' }

if ($PythonPath.Contains('%') -or $NativeDir.Contains('%') -or $PythonPath.Contains('"') -or $NativeDir.Contains('"')) {
    throw 'Install and Python paths cannot contain percent signs or double quotes.'
}

$PythonForBatch = $PythonPath
if ($PythonForBatch -match '[^\x00-\x7F]') {
    try {
        $Fso = New-Object -ComObject Scripting.FileSystemObject
        $Short = $Fso.GetFile($PythonPath).ShortPath
        if ($Short -and ($Short -notmatch '[^\x00-\x7F]')) { $PythonForBatch = $Short }
    } catch {}
}

# Batch file must produce zero stdout/stderr output: Firefox uses stdout for binary IPC.
# %~dp0 resolves the batch directory via Unicode APIs without hardcoding non-ASCII paths.
$Launcher = Join-Path $NativeDir 'host.cmd'
$Lines = @('@echo off')
if ($PythonForBatch -match '[^\x00-\x7F]') {
    $Lines += 'chcp 65001 >nul 2>nul'
}
$Lines += 'set "PYTHONUTF8=1"'
$Lines += 'set "PYTHONIOENCODING=utf-8"'
$Lines += "`"$PythonForBatch`" -u `"%~dp0host.py`""
$Batch = ($Lines -join "`r`n") + "`r`n"
[IO.File]::WriteAllText($Launcher, $Batch, [Text.UTF8Encoding]::new($false))

$ManifestPath = Join-Path $NativeDir 'io.foxtunnel.host.json'
$Manifest = @{
    name = 'io.foxtunnel.host'
    description = 'FoxTunnel sing-box native messaging host'
    path = $Launcher
    type = 'stdio'
    allowed_extensions = @('foxtunnel@local')
} | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($ManifestPath, $Manifest, [Text.UTF8Encoding]::new($false))

$RegistryPath = 'HKCU:\Software\Mozilla\NativeMessagingHosts\io.foxtunnel.host'
$Existing = if (Test-Path $RegistryPath) { (Get-Item $RegistryPath).GetValue('') } else { $null }
if ($Existing -and $Existing -ne $ManifestPath) {
    throw "A different FoxTunnel host is already registered: $Existing. Uninstall it first using native\uninstall.ps1."
}
New-Item -Path $RegistryPath -Force | Out-Null
Set-Item -Path $RegistryPath -Value $ManifestPath

Write-Host 'FoxTunnel native host registered for the current Windows user.'
Write-Host "Python: $PythonPath"
Write-Host "Manifest: $ManifestPath"
Write-Host 'No administrator permissions or system VPN changes were needed.'
Write-Host 'Load extension\manifest.json using about:debugging in Firefox, then add a profile.'
