param(
    [string]$RuntimeIdentifier = "win-x64"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$exe = Join-Path $dist "SyslogPusher.exe"
$staging = Join-Path $root "artifacts\publish"
$serviceName = "SyslogPusher"

function Stop-SyslogPusherBeforePublish {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Host "Service '$serviceName' is not installed."
    }
    elseif ($service.Status -ne "Stopped") {
        Write-Host "Stopping Windows service '$serviceName' (was $($service.Status))..."
        try {
            Stop-Service -Name $serviceName -Force
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            Write-Host "Service stopped."
        }
        catch {
            Write-Warning "Stop-Service failed: $_"
            Write-Host "Trying sc.exe stop..."
            & sc.exe stop $serviceName | Out-Host
            Start-Sleep -Seconds 3
            $service.Refresh()
            if ($service.Status -ne "Stopped") {
                Write-Warning "Service may still be running. Run this script as Administrator."
            }
        }
    }
    else {
        Write-Host "Service '$serviceName' is already stopped."
    }

    $processes = Get-Process -Name "SyslogPusher" -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        Write-Host "Ending SyslogPusher process (PID $($process.Id))..."
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }

    if ($processes) {
        Start-Sleep -Seconds 2
    }

    if (Test-Path $exe) {
        try {
            $stream = [System.IO.File]::Open(
                $exe,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
            $stream.Close()
        }
        catch {
            Write-Warning "SyslogPusher.exe is locked at '$exe' (is the service or UI still running?)."
        }
    }
}

Stop-SyslogPusherBeforePublish

if (Test-Path $staging) {
    Remove-Item $staging -Recurse -Force
}
New-Item -ItemType Directory -Path $dist -Force | Out-Null
New-Item -ItemType Directory -Path $staging -Force | Out-Null

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
dotnet publish (Join-Path $root "src\SyslogPusher.Service\SyslogPusher.Service.csproj") @publishArgs

$published = Join-Path $staging "SyslogPusher.exe"
if (-not (Test-Path $published)) {
    throw "Expected $published was not created."
}

$outputExe = $exe
try {
    Copy-Item $published $exe -Force
}
catch {
    $outputExe = Join-Path $dist "SyslogPusher.new.exe"
    Copy-Item $published $outputExe -Force
    Write-Warning "Could not overwrite $exe. New build saved as $outputExe"
    Write-Warning "Stop the service, replace the file, then run Upgrade or sc start $serviceName"
}

Remove-Item $staging -Recurse -Force

$sizeMb = [math]::Round((Get-Item $outputExe).Length / 1MB, 1)
Write-Host ""
Write-Host "Published: $outputExe ($sizeMb MB)"
Write-Host "One executable: UI when launched interactively, service when started by Windows."
if ($outputExe -eq $exe) {
    Write-Host "Restart the service from Maintenance (Upgrade) or: sc start $serviceName"
}
