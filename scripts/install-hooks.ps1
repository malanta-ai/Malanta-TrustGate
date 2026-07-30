# install-hooks.ps1
#
# Windows installer for the Malanta TrustGate Cursor hooks. Mirrors
# scripts/install-hooks.sh:
#   1. Builds the hook binaries with `go build` (produces .exe on Windows).
#   2. Installs them under %USERPROFILE%\.local\bin\.
#   3. Writes %USERPROFILE%\.cursor\hooks.json from hooks.json
#      (substituting HOME_PLACEHOLDER -> $env:USERPROFILE and EXT_PLACEHOLDER -> .exe).
#   4. Installs the TrustGate agent skill into %USERPROFILE%\.cursor\skills\
#      (so the agent reads verdicts correctly); skip with -NoAgentGuidance.
#   5. Stores MALANTA_API_KEY in %USERPROFILE%\.config\trustgate\env, ACL-restricted
#      to the current user (the Windows equivalent of mode 0600).
#
# Idempotent: re-running overwrites binaries, hooks.json, and the agent skill,
# but preserves any existing API key file unless -ResetKey is passed.
#
# Usage:
#   pwsh -File scripts\install-hooks.ps1
#   pwsh -File scripts\install-hooks.ps1 -ResetKey
#   pwsh -File scripts\install-hooks.ps1 -NoAgentGuidance
#   pwsh -File scripts\install-hooks.ps1 -Prebuilt
#
#   -Prebuilt   Don't build from source (no Go toolchain needed). Download
#               the matching prebuilt binaries for this arch from the internal
#               binaries repo (malanta-ai/Malanta-TrustGate-Binaries), verify
#               their SHA-256, and install those. Requires access to that repo.
#
# Requirements:
#   - PowerShell 5.1 or 7+ (works in both).
#   - Go 1.25+ on PATH for a source build (`go version` must succeed), OR
#     -Prebuilt (needs git + access to the binaries repo instead).

[CmdletBinding()]
param(
    [switch]$ResetKey,
    [switch]$NoAgentGuidance,
    [switch]$Prebuilt
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$binDir    = Join-Path $env:USERPROFILE ".local\bin"
$cfgDir    = Join-Path $env:USERPROFILE ".config\trustgate"
$cursorDir = Join-Path $env:USERPROFILE ".cursor"
$keyFile   = Join-Path $cfgDir "env"

$binariesRepoUrl = "https://github.com/malanta-ai/Malanta-TrustGate-Binaries.git"

New-Item -ItemType Directory -Force -Path $binDir, $cfgDir, $cursorDir | Out-Null

# Lock the config directory down to the current user only. This is the
# Windows equivalent of `chmod 700` - remove inherited ACEs and grant
# FullControl to the current user.
& icacls $cfgDir /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null

if ($Prebuilt) {
    # Download prebuilt binaries instead of building — the no-Go path.
    # Clones the internal binaries repo, verifies SHA-256, extracts this
    # arch's zip into dist\ so the install step below is identical.
    $version = (Get-Content -Raw (Join-Path $repoRoot ".cursor-plugin\plugin.json") | ConvertFrom-Json).version
    if (-not $version) { Write-Error "could not read plugin version from .cursor-plugin/plugin.json"; exit 1 }
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $arch = "amd64" }
        "ARM64" { $arch = "arm64" }
        default { Write-Error "unsupported arch $($env:PROCESSOR_ARCHITECTURE)"; exit 1 }
    }
    $archive = "trustgate_${version}_windows_${arch}.zip"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tg-prebuilt-" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Write-Host "==> Fetching prebuilt binaries ($archive) from $binariesRepoUrl"
        & git clone --depth 1 $binariesRepoUrl (Join-Path $tmp "bin") 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Error "could not clone $binariesRepoUrl - do you have access to that private repo?"; exit 1 }
        $rel = Join-Path $tmp "bin\v$version"
        $archivePath = Join-Path $rel $archive
        if (-not (Test-Path $archivePath)) { Write-Error "$archive not found in the binaries repo (v$version)"; exit 1 }
        Write-Host "==> Verifying SHA-256 checksum"
        $expected = (Select-String -Path (Join-Path $rel "SHA256SUMS") -Pattern ([regex]::Escape($archive)) | Select-Object -First 1).Line.Split(" ")[0].Trim()
        $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
        if ($expected -ne $actual) { Write-Error "checksum verification failed for $archive (expected $expected, got $actual)"; exit 1 }
        New-Item -ItemType Directory -Force -Path "dist" | Out-Null
        Expand-Archive -Path $archivePath -DestinationPath "dist" -Force
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
else {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        $goDlUrl = "https://" + "go" + ".dev/dl/"
        Write-Error ("go toolchain not found on PATH. Install Go 1.25+ from " + $goDlUrl + " and retry, or re-run with -Prebuilt to download prebuilt binaries instead.")
        exit 1
    }

    Write-Host "==> Building binaries"
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    go build -o dist/ ./cmd/...
    if ($LASTEXITCODE -ne 0) {
        Write-Error "go build failed"
        exit $LASTEXITCODE
    }
}

# Five hook binaries plus the trustgate admin CLI. `trustgate-before-prompt`
# (beforeSubmitPrompt) is now wired as an early warn-mode surface: it warns
# on a flagged domain the user types with an action verb, and the accepted
# grant is honored by the execution hooks (see docs/admin.md §5). It is
# installed here AND registered in hooks.json in the SAME pass, per
# AGENTS.md §3 ("Install in the correct order"). Kept aligned with
# `scripts/install-hooks.sh`.
$binaries = @(
    "trustgate-before-prompt",
    "trustgate-before-shell",
    "trustgate-before-mcp",
    "trustgate-before-read-file",
    "trustgate-before-tool-use",
    "trustgate"
)

Write-Host "==> Installing binaries to $binDir"
foreach ($name in $binaries) {
    $src = Join-Path "dist" "$name.exe"
    $dst = Join-Path $binDir "$name.exe"
    Copy-Item -Path $src -Destination $dst -Force
}

Write-Host "==> Writing hooks.json to $cursorDir\hooks.json"
# JSON tolerates forward slashes in string values and the Go runtime resolves
# them correctly on Windows, so we normalize separators to '/' for the manifest
# to keep the file diff-friendly across platforms.
$binDirForJson = $binDir -replace '\\', '/'

$hooksTemplate = Get-Content -Raw -Path (Join-Path $repoRoot "hooks.json")
# Defense in depth: drop a leading UTF-8 BOM if the template somehow has one.
$hooksTemplate = $hooksTemplate.TrimStart([char]0xFEFF)
$hooksJson = $hooksTemplate `
    -replace 'HOME_PLACEHOLDER/.local/bin', $binDirForJson `
    -replace 'EXT_PLACEHOLDER', '.exe'
# Write WITHOUT a BOM. On Windows PowerShell 5.1, `Set-Content -Encoding UTF8`
# prepends a UTF-8 BOM (EF BB BF); Go's encoding/json then fails to parse the
# manifest / payload with "invalid character 'ï'". Use .NET WriteAllText with
# a BOM-less UTF8Encoding, which behaves identically on PS 5.1 and 7+.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $cursorDir "hooks.json"), $hooksJson, $utf8NoBom)

# Install the TrustGate agent skill into the user-global skills dir
# (~/.cursor/skills/<name>/SKILL.md) so the agent loads it on demand and
# reads verdicts correctly. Mirrors scripts/install-hooks.sh. The always-on
# RULE has no user-global file path in Cursor, so it's surfaced in the
# "Next steps" note instead of installed.
$skillSrc = Join-Path $repoRoot "skills\trustgate\SKILL.md"
$skillDstDir = Join-Path $cursorDir "skills\trustgate"
if ((-not $NoAgentGuidance) -and (Test-Path $skillSrc)) {
    Write-Host "==> Installing agent skill to $skillDstDir"
    New-Item -ItemType Directory -Force -Path $skillDstDir | Out-Null
    Copy-Item -Path $skillSrc -Destination (Join-Path $skillDstDir "SKILL.md") -Force
}

# API key handling delegates to the trustgate CLI's own "setup"
# subcommand (cmd/trustgate/setup.go), which writes the same file and
# applies the same icacls lockdown this script used to do inline — one
# implementation, one set of tests, exercised on both platforms. The
# existence check stays here so re-running this installer with an
# existing key file is a silent no-op (matching this script's documented
# idempotent behavior) instead of $ErrorActionPreference="Stop" aborting
# the whole install on setup's "already exists, pass -Reset" refusal.
if ((Test-Path $keyFile) -and (-not $ResetKey)) {
    Write-Host "==> $keyFile already exists; leaving in place (pass -ResetKey to overwrite)"
}
else {
    $trustgateExe = Join-Path $binDir "trustgate.exe"
    if ($ResetKey) {
        & $trustgateExe setup --reset
    }
    else {
        & $trustgateExe setup
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "trustgate setup failed"
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "Installed. Next steps:"
Write-Host "  1. Restart Cursor so it picks up the new hooks."
Write-Host "  2. Try a benign action (open a project, ask a normal question)."
Write-Host "  3. Tail the decision log to watch verdicts:"
Write-Host ('       Get-Content -Wait "{0}\.cache\trustgate\decisions.log"' -f $env:USERPROFILE)

$ruleSrc = Join-Path $repoRoot "rules\trustgate-modes.mdc"
if ((-not $NoAgentGuidance) -and (Test-Path $ruleSrc)) {
    Write-Host ""
    Write-Host "Agent guidance:"
    Write-Host "  - Installed the TrustGate skill at $skillDstDir\SKILL.md (loads on demand)."
    Write-Host "  - The always-on verdict rule can't be installed as a global file"
    Write-Host "    (Cursor has no user-global rule file path). To make it always-on, paste"
    Write-Host "    $ruleSrc into Cursor -> Settings -> Customize -> Rules (User Rules),"
    Write-Host "    or copy it into a project's .cursor\rules\ for per-project scope."
}
