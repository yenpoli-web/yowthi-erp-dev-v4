param(
    [Parameter(Mandatory = $true)]
    [string]$ProbeValue
)

[ordered]@{
    probe = "YowThi-v4.4-PowerShell-E2E"
    argument = $ProbeValue
    computerName = $env:COMPUTERNAME
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    processId = $PID
    workingDirectory = (Get-Location).Path
    utc = [DateTimeOffset]::UtcNow.ToString("O")
} | ConvertTo-Json -Compress
