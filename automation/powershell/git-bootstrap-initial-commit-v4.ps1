$ErrorActionPreference = 'Stop'
$repo = 'C:\Dev\YowThi-ERP-Dev-v4'
$git = 'C:\Program Files\Git\cmd\git.exe'

if (-not (Test-Path -LiteralPath (Join-Path $repo '.git') -PathType Container)) {
    throw "Git repository is not initialized: $repo"
}

$oldPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $git -c "safe.directory=$repo" -C $repo show-ref --verify --quiet refs/heads/main
$hasMainCommit = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $oldPreference
if ($hasMainCommit) {
    throw 'Initial commit already exists; bootstrap script refuses to run.'
}

$userName = (& $git -c "safe.directory=$repo" -C $repo config --get user.name).Trim()
$userEmail = (& $git -c "safe.directory=$repo" -C $repo config --get user.email).Trim()
if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($userEmail)) {
    throw 'Git user.name and user.email must already be configured before the initial commit.'
}

$paths = @('.gitignore', 'ARCHITECTURE-CONTRACT-v1.md', 'automation', 'src')
foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath (Join-Path $repo $path))) {
        throw "Required bootstrap path not found: $path"
    }
}

& $git -c "safe.directory=$repo" -C $repo add -- .gitignore ARCHITECTURE-CONTRACT-v1.md automation src
if ($LASTEXITCODE -ne 0) {
    throw "git add failed with exit code $LASTEXITCODE"
}

$oldPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $git -c "safe.directory=$repo" -C $repo diff --cached --quiet
$hasNoStagedChanges = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $oldPreference
if ($hasNoStagedChanges) {
    throw 'No staged changes found for the initial commit.'
}

& $git -c "safe.directory=$repo" -C $repo -c core.hooksPath=NUL commit --no-gpg-sign --no-verify -m 'chore: initialize YowThi ERP Dev v4 repository'
if ($LASTEXITCODE -ne 0) {
    throw "git commit failed with exit code $LASTEXITCODE"
}

$head = (& $git -c "safe.directory=$repo" -C $repo rev-parse --verify HEAD).Trim()
Write-Output "committed:$head;branch=main;author=$userName <$userEmail>"
