param(
    [string]$RuntimeIdentifier = "win-x64"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$exe = Join-Path $dist "SyslogPusher.exe"
$staging = Join-Path $root "artifacts\publish"

if (Test-Path $dist) {
    Remove-Item $dist -Recurse -Force
}
if (Test-Path $staging) {
    Remove-Item $staging -Recurse -Force
}
New-Item -ItemType Directory -Path $dist -Force | Out-Null

$publishArgs = @(
    "-c", "Release",
    "-o", $staging,
    "--self-contained", "true",
    "-r", $RuntimeIdentifier,
    "-p:PublishSingleFile=true",
    "-p:IncludeNativeLibrariesForSelfExtract=true",
    "-p:EnableCompressionInSingleFile=true",
    "-p:DebugType=none",
    "-p:DebugSymbols=false"
)

Write-Host "Publishing single-file SyslogPusher.exe (self-contained, $RuntimeIdentifier)..."
dotnet publish (Join-Path $root "src\SyslogPusher.UI\SyslogPusher.UI.csproj") @publishArgs

$published = Join-Path $staging "SyslogPusher.exe"
if (-not (Test-Path $published)) {
    throw "Expected $published was not created."
}

Copy-Item $published $exe -Force
Remove-Item $staging -Recurse -Force

$sizeMb = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host ""
Write-Host "Published: $exe ($sizeMb MB)"
Write-Host "Distribute this single file. The .NET runtime is bundled inside it."
Write-Host "The Windows service uses the same executable with --service."
