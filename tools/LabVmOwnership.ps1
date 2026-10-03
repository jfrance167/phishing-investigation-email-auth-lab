function Assert-LabVmTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$VmInfo,
        [Parameter(Mandatory)][string]$ExpectedConfig,
        [Parameter(Mandatory)][switch]$ConfirmFreshLogin
    )

    if (-not $ConfirmFreshLogin.IsPresent) {
        throw 'Explicit -ConfirmFreshLogin assertion is required before console input.'
    }

    $taskConfigLines = @($VmInfo | Where-Object { $_ -match '^CfgFile=' })
    if ($taskConfigLines.Count -ne 1) { throw 'Expected exactly one VM configuration path.' }
    $taskActualConfig = [IO.Path]::GetFullPath(($taskConfigLines[0] -replace '^CfgFile=', '').Trim('"'))
    $taskExpectedFullPath = [IO.Path]::GetFullPath($ExpectedConfig)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($taskActualConfig, $taskExpectedFullPath)) {
        throw 'VM configuration path does not match the owned lab guest.'
    }

    if (-not ($VmInfo -contains 'VMState="running"')) {
        throw 'The owned guest must be running at its fresh tty login prompt.'
    }
}
