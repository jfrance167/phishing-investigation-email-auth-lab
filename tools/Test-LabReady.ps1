param([Parameter(Mandatory)][string]$OutputDirectory,[switch]$IncludeRelay)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskVBox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$taskKnownHostsOption = 'UserKnownHostsFile="' + (Join-Path $taskRoot '.private/known_hosts') + '"'
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a fresh evidence directory' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
if (@(Get-NetIPInterface | Where-Object Forwarding -eq Enabled).Count) { throw 'Host forwarding enabled' }
$taskRoles = @('sender','receiver')
if ($IncludeRelay) { $taskRoles += 'relay' }
foreach ($taskRole in $taskRoles) {
 $taskVM = "PEAL-$taskRole"
 $taskInfo = @(& $taskVBox showvminfo $taskVM --machinereadable)
 if ($LASTEXITCODE) { throw 'VM inventory failed' }
 foreach ($taskRequired in @('nic1="hostonly"','hostonlyadapter1="VirtualBox Host-Only Ethernet Adapter"','nic2="intnet"','intnet2="PEAL-experiment"','nic3="none"','nic4="none"','nic5="none"','nic6="none"','nic7="none"','nic8="none"')) {
  if ($taskInfo -notcontains $taskRequired) { throw "Unsafe/missing NIC setting on $taskVM" }
 }
 $taskConfigLine = @($taskInfo | Where-Object { $_ -match '^CfgFile=' })
 $taskExpectedConfig = [IO.Path]::GetFullPath((Join-Path $taskRoot ".private/vms/$taskVM/$taskVM.vbox"))
 if ($taskConfigLine.Count -ne 1 -or [IO.Path]::GetFullPath(($taskConfigLine[0] -replace '^CfgFile="|"$','')) -ne $taskExpectedConfig) { throw 'VM ownership mismatch' }
 $taskInfo | Set-Content (Join-Path $OutputDirectory "$taskRole-vbox.txt")
 $taskAddress = @{sender='192.168.56.50';receiver='192.168.56.51';relay='192.168.56.52'}[$taskRole]
 & 'C:\Windows\System32\OpenSSH\scp.exe' -i (Join-Path $taskRoot '.private/id_ed25519') -o BatchMode=yes -o StrictHostKeyChecking=yes -o $taskKnownHostsOption (Join-Path $PSScriptRoot 'guest_validate.py') "root@${taskAddress}:/opt/peal/guest_validate.py"
 if ($LASTEXITCODE) { throw 'Validation script transfer failed' }
 $taskResult = & 'C:\Windows\System32\OpenSSH\ssh.exe' -i (Join-Path $taskRoot '.private/id_ed25519') -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o $taskKnownHostsOption "root@$taskAddress" "python3 /opt/peal/guest_validate.py $taskRole"
 $taskResult | Set-Content (Join-Path $OutputDirectory "$taskRole-gate.json")
 if ($LASTEXITCODE) { throw "Guest runtime gate failed: $taskRole" }
 $taskParsed = ($taskResult -join "`n") | ConvertFrom-Json
 if ([Math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $taskParsed.collected_unix) -gt 10) { throw 'Guest clock differs by more than 10 seconds' }
}
Write-Output 'Static runtime gate passed. Preserve and review connectivity evidence before baseline.'
