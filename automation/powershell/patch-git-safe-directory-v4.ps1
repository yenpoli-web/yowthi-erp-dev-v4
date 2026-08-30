$ErrorActionPreference = 'Stop'
$files = @(
    'C:\Dev\YowThi-ERP-Dev-v4\src\YowThi.DevelopmentAgent3\Git\GitTools.cs',
    'C:\Dev\YowThi-ERP-Dev-v4\src\YowThi.DevelopmentAgent3\Git\GitV2Tools.cs'
)

foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Source file not found: $file"
    }

    $text = [System.IO.File]::ReadAllText($file)
    $oldCrLf = "        psi.ArgumentList.Add(`"-C`");`r`n        psi.ArgumentList.Add(repository);"
    $newCrLf = "        psi.ArgumentList.Add(`"-c`");`r`n        psi.ArgumentList.Add($`"safe.directory={repository}`");`r`n        psi.ArgumentList.Add(`"-C`");`r`n        psi.ArgumentList.Add(repository);"
    $oldLf = "        psi.ArgumentList.Add(`"-C`");`n        psi.ArgumentList.Add(repository);"
    $newLf = "        psi.ArgumentList.Add(`"-c`");`n        psi.ArgumentList.Add($`"safe.directory={repository}`");`n        psi.ArgumentList.Add(`"-C`");`n        psi.ArgumentList.Add(repository);"

    if ($text.Contains($newCrLf) -or $text.Contains($newLf)) {
        throw "safe.directory patch already present: $file"
    }

    if ($text.Contains($oldCrLf)) {
        $updated = $text.Replace($oldCrLf, $newCrLf)
    }
    elseif ($text.Contains($oldLf)) {
        $updated = $text.Replace($oldLf, $newLf)
    }
    else {
        throw "Expected Git ArgumentList marker not found: $file"
    }

    [System.IO.File]::WriteAllText($file, $updated, [System.Text.UTF8Encoding]::new($false))
    Write-Output "patched:$file"
}
