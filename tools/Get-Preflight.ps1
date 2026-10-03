param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Output) { throw 'Choose a fresh output file' }
$taskResult = [ordered]@{
    collected_utc = [DateTime]::UtcNow.ToString('o')
    os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,FreePhysicalMemory,TotalVisibleMemorySize
    cpu = Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions
    hypervisor = Get-CimInstance Win32_ComputerSystem | Select-Object HypervisorPresent
    disk = Get-PSDrive C | Select-Object Name,Used,Free
    forwarding = @(Get-NetIPInterface | Select-Object InterfaceAlias,AddressFamily,Forwarding)
    vbox_version = & 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' --version
    running_vms = @(& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' list runningvms)
    hostonly = @(& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' list hostonlyifs)
}
$taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output -Encoding utf8
