$ErrorActionPreference = 'Stop'
$repo = 'C:\Dev\YowThi-ERP-Dev-v4'
$git = 'C:\Program Files\Git\cmd\git.exe'
$gitDir = Join-Path $repo '.git'

if (-not (Test-Path -LiteralPath $repo -PathType Container)) {
    throw "Repository directory not found: $repo"
}
if (-not (Test-Path -LiteralPath $git -PathType Leaf)) {
    throw "git.exe not found: $git"
}
if (Test-Path -LiteralPath $gitDir) {
    throw "Git repository already initialized: $gitDir"
}

& $git -C $repo init -b main .
if ($LASTEXITCODE -ne 0) {
    throw "git init failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $gitDir -PathType Container)) {
    throw "Git repository initialization did not create: $gitDir"
}

Write-Output "initialized:$repo;branch=main"
