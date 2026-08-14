$engine = ".\SentinelGrid\build\SentinelGrid.Engine.App\x64\Debug\bin\SentinelGrid.Engine.App.exe"
$agent = ".\SentinelGrid\x64\Debug\SentinelGrid.Agent.App.exe"


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

$env:Path = "$($asanDll.DirectoryName);$env:Path"

# Start server, then client
$engineCommand = "& '$engine'"
$agentCommand  = "& '$agent'"

Start-Process powershell.exe -ArgumentList `
    "-NoExit", "-Command", $engineCommand

Start-Sleep -Milliseconds 500

Start-Process powershell.exe -ArgumentList `
    "-NoExit", "-Command", $agentCommand