$ErrorActionPreference = "Stop"

# Distribution target: 64-bit Intel/AMD Windows only (PE machine type AMD64).
$RuntimeIdentifier = "win-x64"

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$propsPath = Join-Path $root "Directory.Build.props"
$props = [xml](Get-Content $propsPath -Raw)
$version = [string]($props.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Version was not found in $propsPath"
}
$assemblyFileVersion = "$version.0"
$exeName = "SyslogPusher-$version.exe"
$exe = Join-Path $dist $exeName
$staging = Join-Path $root "artifacts\publish"
$serviceName = "SyslogPusher"

function Assert-Amd64PeExecutable {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 2) -ne "MZ") {
        throw "Published file is not a valid Windows executable: $Path"
    }

    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -lt 0 -or ($peOffset + 6) -gt $bytes.Length) {
        throw "Published file has an invalid PE header: $Path"
    }

    # IMAGE_FILE_MACHINE_AMD64 = 0x8664
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne 0x8664) {
        throw "Expected amd64/x64 executable (PE machine 0x8664), got 0x{0:X4}: {1}" -f $machine, $Path
    }
}

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
            Write-Warning "$exeName is locked at '$exe' (is the service or UI still running?)."
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
    "-p:DebugSymbols=false",
    "-p:Version=$version",
    "-p:AssemblyVersion=$assemblyFileVersion",
    "-p:FileVersion=$assemblyFileVersion",
    "-p:InformationalVersion=$version"
)

Write-Host "Publishing single-file $exeName (self-contained, amd64/x64)..."
dotnet publish (Join-Path $root "src\SyslogPusher.Service\SyslogPusher.Service.csproj") @publishArgs

$published = Join-Path $staging "SyslogPusher.exe"
if (-not (Test-Path $published)) {
    throw "Expected $published was not created."
}

Assert-Amd64PeExecutable -Path $published

$outputExe = $exe
try {
    Copy-Item $published $exe -Force
}
catch {
    $outputExe = Join-Path $dist "SyslogPusher-$version.new.exe"
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
