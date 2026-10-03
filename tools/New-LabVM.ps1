param([Parameter(Mandatory)][ValidateSet('sender','receiver','relay')][string]$Role)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskVBox = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$taskName = "PEAL-$Role"
$taskIso = Join-Path $taskRoot '.private/debian-13.7.0-amd64-netinst.iso'
$taskExpected = 'a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355'
if ((Get-FileHash -LiteralPath $taskIso).Hash.ToLower() -ne $taskExpected) { throw 'Installer hash mismatch' }
if ((Get-PSDrive C).Free -lt 8GB) { throw 'Need at least 8 GiB free host disk' }
$taskInventory = & $taskVBox list vms
if ($taskInventory -match ('"' + [regex]::Escape($taskName) + '"')) { throw 'Named VM exists; inspect it instead of overwriting' }
$taskPub = (Get-Content -LiteralPath (Join-Path $taskRoot '.private/id_ed25519.pub') -Raw).Trim()
if ($taskPub -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ [A-Za-z0-9-]+$') { throw 'Unexpected public-key format' }
$taskSizes = @{sender=@(1536,2,6144,22710);receiver=@(2048,2,8192,22720);relay=@(1024,1,6144,22730)}
$taskSize = $taskSizes[$Role]
$taskBase = Join-Path $taskRoot '.private/vms'
$taskDisk = Join-Path $taskBase "$taskName/$taskName.vdi"
$taskPasswordFile = Join-Path $taskRoot ".private/$Role-install-password.txt"
[IO.File]::WriteAllText($taskPasswordFile, [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)))
function Invoke-LabVBox([string[]]$Arguments) {
    if ($Arguments[0] -eq 'unattended') {
        # VBox prints passwords even when supplied through a file. Keep all installer output private.
        & $taskVBox @Arguments *> (Join-Path $taskRoot ".private/$Role-installer.log")
    } else { & $taskVBox @Arguments }
    if ($LASTEXITCODE -ne 0) { throw "VirtualBox failed: $($Arguments[0])" }
}
Invoke-LabVBox @('createvm','--name',$taskName,'--ostype','Debian_64','--basefolder',$taskBase,'--register')
Invoke-LabVBox @('modifyvm',$taskName,'--memory',"$($taskSize[0])",'--cpus',"$($taskSize[1])",'--nic1','nat','--natpf1',"provision-ssh,tcp,127.0.0.1,$($taskSize[3]),,22",'--nic2','none','--clipboard-mode','disabled','--drag-and-drop','disabled','--audio-enabled','off','--usb-ohci','off','--boot1','dvd','--boot2','disk','--boot3','none','--boot4','none')
Invoke-LabVBox @('createmedium','disk','--filename',$taskDisk,'--size',"$($taskSize[2])",'--format','VDI')
Invoke-LabVBox @('storagectl',$taskName,'--name','SATA','--add','sata','--controller','IntelAhci','--portcount','2')
Invoke-LabVBox @('storageattach',$taskName,'--storagectl','SATA','--port','0','--device','0','--type','hdd','--medium',$taskDisk)
# Installer shell runs in the target via the installed, inspected VirtualBox template.
$taskPost = "/bin/sh -c 'mkdir -p /target/root/.ssh; chmod 700 /target/root/.ssh; echo $taskPub > /target/root/.ssh/authorized_keys; chmod 600 /target/root/.ssh/authorized_keys; echo PEAL-$Role > /target/etc/peal-owned'"
Invoke-LabVBox @('unattended','install',$taskName,"--iso=$taskIso",'--user=lab',"--user-password-file=$taskPasswordFile",'--hostname',"$Role.test",'--locale=en_US','--time-zone=UTC','--package-selection-adjustment=minimal','--no-install-additions',"--post-install-command=$taskPost",'--start-vm=headless')
Write-Output 'Provisioning only: NAT is active. Experiments are prohibited until isolation is verified.'
