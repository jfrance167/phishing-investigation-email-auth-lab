$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\tools\LabVmOwnership.ps1')

$taskRoot = Join-Path ([IO.Path]::GetTempPath()) ('peal-vm-guard-' + [guid]::NewGuid().ToString('N'))
$taskExpected = Join-Path $taskRoot '.private\vms\PEAL-sender\PEAL-sender.vbox'
$taskOther = Join-Path $taskRoot 'copied-phishing-investigation-email-auth-lab\PEAL-sender.vbox'

function Assert-Rejected([scriptblock]$Action, [string]$Name) {
    try { & $Action }
    catch { return }
    throw "Expected guard to reject: $Name"
}

$taskOwnedRunning = @("CfgFile=`"$taskExpected`"", 'VMState="running"')
Assert-LabVmTarget -VmInfo $taskOwnedRunning -ExpectedConfig $taskExpected -ConfirmFreshLogin

Assert-Rejected {
    Assert-LabVmTarget -VmInfo @("CfgFile=`"$taskExpected`"", 'VMState="running"') -ExpectedConfig $taskExpected
} 'missing operator assertion'

Assert-Rejected {
    Assert-LabVmTarget -VmInfo @("CfgFile=`"$taskOther`"", 'VMState="running"') -ExpectedConfig $taskExpected -ConfirmFreshLogin
} 'similar but non-owned VM path'

Assert-Rejected {
    Assert-LabVmTarget -VmInfo @("CfgFile=`"$taskExpected`"", 'VMState="poweroff"') -ExpectedConfig $taskExpected -ConfirmFreshLogin
} 'powered-off VM'

Assert-Rejected {
    Assert-LabVmTarget -VmInfo @('VMState="running"') -ExpectedConfig $taskExpected -ConfirmFreshLogin
} 'missing configuration path'

Write-Output 'Offline VM ownership/fresh-login guard tests passed.'
