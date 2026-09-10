param([string]$Plugins = '')
$ErrorActionPreference = 'Stop'
if (-not $Plugins) {
    if ($env:IDAUSR) {
        $userRoot = ($env:IDAUSR -split ';')[0]
    } elseif ($env:APPDATA) {
        $userRoot = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro'
    } else {
        throw 'Cannot determine the IDA user directory. Supply -Plugins explicitly.'
    }
    $Plugins = Join-Path $userRoot 'plugins'
}
$destination = [System.IO.Path]::GetFullPath($Plugins)
$package = Join-Path $destination 'covexplorer'
New-Item -ItemType Directory -Path $package -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'coverage_explorer.py') -Destination $destination -Force
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'covexplorer') -Filter '*.py' -File |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $package -Force }
Write-Host "Installed Coverage Explorer in $destination"
Write-Host 'Restart IDA, open a binary, wait for analysis, then press Ctrl+Alt+C.'
