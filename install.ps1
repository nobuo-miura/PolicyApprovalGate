# Install policygate on Windows.
#
# The binary goes to %USERPROFILE%\.policygate\bin, which needs no elevation:
# policygate guards its own executable wherever it is installed, so the install
# location is a matter of convenience rather than of protection.
#
# Download this script, read it, then run it. Piping a downloaded script
# straight into a shell is what policygate's own rules deny, and a tool that
# asks you to trust an unread script has no business telling you not to.
#
# This file is ASCII only, on purpose. Windows PowerShell 5.1 - the version
# Windows ships with - reads a BOM-less UTF-8 script as ANSI, so a non-ASCII
# character anywhere in it becomes a syntax error on the machines most likely
# to run this.

[CmdletBinding()]
param(
    # Install a specific release. Defaults to the newest published one.
    [string]$Version = '',
    # Install into this directory instead of ~\.policygate\bin.
    [string]$Dir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'nobuo-miura/PolicyApprovalGate'

function Fail($message) {
    Write-Error "install.ps1: $message"
    exit 1
}

# TLS 1.2 is not the default on older Windows PowerShell, and GitHub requires it.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Newer runtimes negotiate this themselves and may not expose the property.
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $Arch = 'amd64' }
    'ARM64' { $Arch = 'arm64' }
    default { Fail "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

# Releases are published as pre-releases until v1.0, and the "latest" endpoint
# does not report those - it answers 404 while every release is a pre-release.
# Listing the releases and taking the newest covers both cases.
if (-not $Version) {
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases" -UseBasicParsing
    } catch {
        Fail "could not list releases: $($_.Exception.Message)"
    }
    # Force an array: a single release comes back as a bare object, and reading
    # .Count off one is an error under Set-StrictMode.
    $releases = @($releases)
    if ($releases.Count -eq 0) {
        Fail 'no releases were found; pass -Version'
    }
    $Version = $releases[0].tag_name
}

$Name = "policygate_${Version}_windows_${Arch}.zip"
$Base = "https://github.com/$Repo/releases/download/$Version"
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("policygate-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null

try {
    Write-Host "install.ps1: downloading $Name ($Version)"
    $archive = Join-Path $Work $Name
    $sums = Join-Path $Work 'SHA256SUMS'
    try {
        Invoke-WebRequest -Uri "$Base/$Name" -OutFile $archive -UseBasicParsing
        Invoke-WebRequest -Uri "$Base/SHA256SUMS" -OutFile $sums -UseBasicParsing
    } catch {
        Fail "download failed: $($_.Exception.Message)"
    }

    # Verify before unpacking. The archive is only opened once its checksum
    # matches the one published with the release.
    $actual = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLowerInvariant()
    # SHA256SUMS is written with a ./ prefix on each name.
    $expected = ''
    foreach ($line in Get-Content -LiteralPath $sums) {
        $fields = $line -split '\s+' | Where-Object { $_ -ne '' }
        if ($fields.Count -ge 2 -and $fields[1] -eq "./$Name") {
            $expected = $fields[0].ToLowerInvariant()
            break
        }
    }
    if (-not $expected) {
        Fail "$Name is not listed in SHA256SUMS"
    }
    if ($actual -ne $expected) {
        Fail "checksum mismatch for ${Name}: expected $expected, actual $actual"
    }
    Write-Host 'install.ps1: checksum verified'

    if (-not $Dir) {
        $Dir = Join-Path $env:USERPROFILE '.policygate\bin'
    }
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null

    Expand-Archive -LiteralPath $archive -DestinationPath $Work -Force
    $unpacked = Join-Path $Work 'policygate.exe'
    if (-not (Test-Path -LiteralPath $unpacked)) {
        Fail 'the archive did not contain policygate.exe'
    }

    # A running executable cannot be replaced in place on Windows, but it can be
    # renamed out of the way first.
    $target = Join-Path $Dir 'policygate.exe'
    if (Test-Path -LiteralPath $target) {
        $old = "$target.old"
        Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        Rename-Item -LiteralPath $target -NewName (Split-Path -Leaf $old) -Force
    }
    Move-Item -LiteralPath $unpacked -Destination $target -Force

    $installed = & $target version
    Write-Host "install.ps1: installed $installed to $target"

    & $target init
    if ($LASTEXITCODE -ne 0) {
        Fail 'could not create the configuration'
    }

    Write-Host ''
    Write-Host 'Next: register the hook with the host you use.'
    Write-Host ''
    Write-Host "  $target install-hook --host claude    # .\.claude\settings.local.json"
    Write-Host "  $target install-hook --host codex     # ~\.codex\config.toml"
    Write-Host ''
    Write-Host 'Claude Code reads its hook settings when a session starts, so restart it afterwards.'
    Write-Host 'Codex needs the definition trusted with /hooks, or the hook is skipped.'
    Write-Host ''
    Write-Host 'Then check the result:'
    Write-Host ''
    Write-Host "  $target doctor"

    $onPath = ($env:PATH -split ';') -contains $Dir
    if (-not $onPath) {
        Write-Host ''
        Write-Host "$Dir is not on your PATH. The hook runs by absolute path and works"
        Write-Host 'regardless, but adding it lets you run policygate by name:'
        Write-Host ''
        Write-Host "  [Environment]::SetEnvironmentVariable('PATH', `"$Dir;`$env:PATH`", 'User')"
    }
} finally {
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}
