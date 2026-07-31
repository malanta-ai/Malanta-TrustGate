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
#               this arch's binaries from the GitHub release matching the
#               version in .cursor-plugin/plugin.json, verify each against
#               that release's signed checksums.txt, and install those.
#
# Requirements:
#   - PowerShell 5.1 or 7+ (works in both).
#   - Go 1.25+ on PATH for a source build (`go version` must succeed), OR
#     -Prebuilt (needs network access to github.com instead).

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

# Release download base (used only by -Prebuilt). Overridable for testing
# against a local fixture, the same escape hatch the plugin resolver has.
$releaseBaseUrl = if ($env:TRUSTGATE_RELEASE_BASE_URL) { $env:TRUSTGATE_RELEASE_BASE_URL } else { "https://github.com/malanta-ai/Malanta-TrustGate/releases/download" }

# The five hook binaries plus the trustgate admin CLI. Declared before the
# build/download step because -Prebuilt fetches exactly this set.
$binaries = @(
    "trustgate-before-prompt",
    "trustgate-before-shell",
    "trustgate-before-mcp",
    "trustgate-before-read-file",
    "trustgate-before-tool-use",
    "trustgate"
)

New-Item -ItemType Directory -Force -Path $binDir, $cfgDir, $cursorDir | Out-Null

# Lock the config directory down to the current user only. This is the
# Windows equivalent of `chmod 700` - remove inherited ACEs and grant
# FullControl to the current user.
& icacls $cfgDir /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null

if ($Prebuilt) {
    # Download prebuilt binaries instead of building - the no-Go path.
    # Same artifacts and same verification chain the Marketplace plugin's
    # resolver uses (hooks/scripts/lib/ensure-binary.sh): SHA-256 against
    # the release's checksums.txt, plus a cosign signature over that file
    # when the cosign CLI is present. One release, no second channel.
    $version = (Get-Content -Raw (Join-Path $repoRoot ".cursor-plugin\plugin.json") | ConvertFrom-Json).version
    if (-not $version) { Write-Error "could not read plugin version from .cursor-plugin/plugin.json"; exit 1 }
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $arch = "amd64" }
        "ARM64" { $arch = "arm64" }
        default { Write-Error "unsupported arch $($env:PROCESSOR_ARCHITECTURE)"; exit 1 }
    }
    $base = "$releaseBaseUrl/v$version"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tg-prebuilt-" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Write-Host "==> Fetching release v$version (windows/$arch) from $base"
        $sumsPath = Join-Path $tmp "checksums.txt"
        Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile $sumsPath -UseBasicParsing

        # Verify the signature over checksums.txt before trusting any digest
        # in it. Absent cosign this degrades to checksum-only, which is
        # same-origin and therefore weaker - warn rather than fail.
        if (Get-Command cosign -ErrorAction SilentlyContinue) {
            $bundlePath = Join-Path $tmp "checksums.txt.sigstore.json"
            try {
                Invoke-WebRequest -Uri "$base/checksums.txt.sigstore.json" -OutFile $bundlePath -UseBasicParsing
                Write-Host "==> Verifying cosign signature over checksums.txt"
                & cosign verify-blob --bundle $bundlePath `
                    --certificate-identity-regexp '^https://github\.com/malanta-ai/Malanta-TrustGate/' `
                    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
                    $sumsPath 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) { Write-Error "cosign signature verification FAILED for checksums.txt - refusing"; exit 1 }
            }
            catch {
                Write-Host "note: this release has no signature bundle; proceeding on SHA-256 only"
            }
        }
        else {
            Write-Host "note: cosign not found - verifying by SHA-256 against the release's own checksums.txt only."
        }

        $sums = @{}
        foreach ($line in (Get-Content $sumsPath)) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2) { $sums[$parts[1].Trim()] = $parts[0].Trim().ToLower() }
        }

        New-Item -ItemType Directory -Force -Path "dist" | Out-Null
        foreach ($name in $binaries) {
            $asset = "${name}_windows_${arch}.exe"
            $assetPath = Join-Path $tmp $asset
            Invoke-WebRequest -Uri "$base/$asset" -OutFile $assetPath -UseBasicParsing
            $expected = $sums[$asset]
            if (-not $expected) { Write-Error "$asset is not listed in checksums.txt; refusing"; exit 1 }
            $actual = (Get-FileHash -Algorithm SHA256 -Path $assetPath).Hash.ToLower()
            if ($expected -ne $actual) { Write-Error "checksum mismatch for $asset (expected $expected, got $actual) - possible tampering; refusing"; exit 1 }
            Move-Item -Force -Path $assetPath -Destination (Join-Path "dist" "$name.exe")
        }
        Write-Host "==> Verified $($binaries.Count) binaries against checksums.txt"
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

# $binaries is declared near the top (the -Prebuilt path needs it too).
# `trustgate-before-prompt` (beforeSubmitPrompt) is wired as an early
# warn-mode surface: it warns on a flagged domain the user types with an
# action verb, and the accepted grant is honored by the execution hooks
# (see docs/admin.md §5). It is installed here AND registered in hooks.json
# in the SAME pass, per AGENTS.md §3 ("Install in the correct order").
# Kept aligned with `scripts/install-hooks.sh`.

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
