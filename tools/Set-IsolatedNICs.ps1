param([Parameter(Mandatory)][ValidateSet('sender','receiver','relay')][string]$Role)
$ErrorActionPreference = 'Stop'
$taskVBox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$taskName = "PEAL-$Role"
$taskInfo = & $taskVBox showvminfo $taskName --machinereadable
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskConfigLine = @($taskInfo | Where-Object { $_ -match '^CfgFile=' })
$taskExpectedConfig = [IO.Path]::GetFullPath((Join-Path $taskRoot ".private/vms/$taskName/$taskName.vbox"))
if ($taskConfigLine.Count -ne 1 -or [IO.Path]::GetFullPath(($taskConfigLine[0] -replace '^CfgFile="|"$','')) -ne $taskExpectedConfig) { throw 'Ownership mismatch' }
if (-not ($taskInfo -contains 'VMState="poweroff"')) { throw 'Guest must be powered off after staging its network' }
if (@(Get-NetIPInterface | Where-Object Forwarding -eq Enabled).Count) { throw 'Host forwarding is enabled; do not silently change it' }
$taskAdapter = 'VirtualBox Host-Only Ethernet Adapter'
& $taskVBox modifyvm $taskName --nic1 hostonly --host-only-adapter1 $taskAdapter --nic2 intnet --intnet2 'PEAL-experiment' --nic3 none --nic4 none --nic5 none --nic6 none --nic7 none --nic8 none --boot1 disk --boot2 none
if ($LASTEXITCODE) { throw 'NIC configuration failed' }
& $taskVBox startvm $taskName --type headless
if ($LASTEXITCODE) { throw 'Guest start failed' }
Write-Output 'NAT removed; must still verify guest routes, firewall and service bindings before experiments.'
