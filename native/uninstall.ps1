$ErrorActionPreference = 'Stop'
$RegistryPath = 'HKCU:\Software\Mozilla\NativeMessagingHosts\io.foxtunnel.host'
$ManifestPath = Join-Path $PSScriptRoot 'io.foxtunnel.host.json'
$LauncherPath = Join-Path $PSScriptRoot 'host.cmd'

if (Test-Path $RegistryPath) {
    $Existing = (Get-Item $RegistryPath).GetValue('')
    if ($Existing -and $Existing -ne $ManifestPath) {
        throw "Registration belongs to a different installation: $Existing. Nothing was removed."
    }
    Remove-Item -Path $RegistryPath
}
if (Test-Path -LiteralPath $ManifestPath) { Remove-Item -LiteralPath $ManifestPath -Force }
if (Test-Path -LiteralPath $LauncherPath) { Remove-Item -LiteralPath $LauncherPath -Force }

Write-Host 'Native host registration removed. No user data, logs or binaries were deleted.'
Write-Host 'Disable/remove the Firefox extension separately. Private runtime data: %LOCALAPPDATA%\FoxTunnel.'
