# Defining to do in case of errors
$ErrorActionPreference = "Stop"

# Defining scripts locations
$repositoryRoot = $PSScriptRoot
$solutionRoot = Join-Path $repositoryRoot 'SentinelGrid'

$engine = Join-Path `
            $solutionRoot `
            "\build\SentinelGrid.Engine.App\x64\Debug\bin\SentinelGrid.Engine.App.exe"

$agent = Join-Path `
            $solutionRoot `
            "\build\SentinelGrid.Agent.App\x64\Debug\bin\SentinelGrid.Agent.App.exe"

$provisioner = Join-Path `
            $solutionRoot `
            "\build\SentinelGrid.Agentkey.Provisioner\x64\Debug\bin\SentinelGrid.Agentkey.Provisioner.exe"


# Ensure executable existence
foreach ($executable in @($engine, $agent, $provisioner)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Executable not found: $executable" 
    }
}

# Locate Visual Studio
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

$vsInstall = & $vswhere `
    -latest `
    -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

if (-not $vsInstall) {
    throw "Visual Studio C++ installation not found."
}

# Locate and expose the ASan runtime
$asanDll = Get-ChildItem `
    -Path "$vsInstall\VC\Tools" `
    -Filter "clang_rt.asan_dynamic-x86_64.dll" `
    -File `
    -Recurse `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $asanDll) {
    throw "AddressSanitizer runtime DLL not found."
}

# Child processes inherit this PATH 
$env:Path = "$($asanDll.DirectoryName);$env:Path"

# Agent IDs definition
$agentIds = @(1, 2)

# Key creation
foreach ($agentId in $agentIds) {
    & $provisioner $agentId --overwrite

    if ($LASTEXITCODE -ne 0) {
        throw "Provisioning failed for agent: $agentId" 
    }
}

# Launching the engine 
$engineProcess = Start-Process powershell.exe -ArgumentList  @("-NoExit", "-Command", $engine) -WorkingDirectory $solutionRoot
# Sleep 1 second lo give the engine the time to load credentials
Start-Sleep -Seconds 1

if ($engineProcess.HasExited) {
    throw "Engine failed before the agents started."
}

$agentProcesses = foreach ($agentId in $agentIds) {
    Start-Process  powershell.exe -ArgumentList  @("-NoExit", "-Command", $agent, $agentId) -WorkingDirectory $solutionRoot
} 

Write-Host "Engine PID: $($engineProcess.Id)"

foreach ($process in $agentProcesses) {
    Write-Host "Agent PID: $($process.Id)"
}