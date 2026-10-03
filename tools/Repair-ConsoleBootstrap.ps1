# Recovery for the first two installations whose custom command targeted the installer root.
# Preconditions: owned, running VM at a fresh tty login prompt. The switch is an
# operator assertion; this script cannot inspect or prove which console is visible.
param(
    [Parameter(Mandatory)][ValidateSet('sender','receiver')][string]$Role,
    [Parameter(Mandatory)][switch]$ConfirmFreshLogin
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskVBox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$taskName = "PEAL-$Role"
$taskInfo = & $taskVBox showvminfo $taskName --machinereadable
if ($LASTEXITCODE -ne 0) { throw 'VirtualBox VM inventory failed' }
. (Join-Path $PSScriptRoot 'LabVmOwnership.ps1')
$taskExpectedConfig = Join-Path $taskRoot ".private/vms/$taskName/$taskName.vbox"
Assert-LabVmTarget -VmInfo $taskInfo -ExpectedConfig $taskExpectedConfig -ConfirmFreshLogin:$ConfirmFreshLogin
$taskPub = (Get-Content -LiteralPath (Join-Path $taskRoot '.private/id_ed25519.pub') -Raw).Trim()
if ($taskPub -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ [A-Za-z0-9-]+$') { throw 'Invalid key' }
function Enter-Console([string]$Value) {
    & $taskVBox controlvm $taskName keyboardputstring $Value | Out-Null
    if ($LASTEXITCODE) { throw 'Console input failed' }
    & $taskVBox controlvm $taskName keyboardputscancode 1c 9c | Out-Null
    if ($LASTEXITCODE) { throw 'Console Enter keystroke failed' }
    Start-Sleep -Milliseconds 500
}
Enter-Console 'root'
Enter-Console ((Get-Content -LiteralPath (Join-Path $taskRoot ".private/$Role-install-password.txt") -Raw).Trim())
Start-Sleep -Seconds 1
Enter-Console "mkdir -p /root/.ssh; chmod 700 /root/.ssh; echo '$taskPub' > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; echo PEAL-$Role > /etc/peal-owned"
Enter-Console 'exit'
Write-Output 'Console bootstrap sent; independently verify key-based SSH and marker.'
