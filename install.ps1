# Script to install and configure ADDS, DHCP and DNS on Windows Server 2022

$filePath = "C:\rcount.txt"
$fileContent = Get-Content -Path $filePath
if ($fileContent -eq "1") {
    Write-Host "First Reboot succeeded, continuing with installation"
    Remove-Item $filePath # remove lockfile
    Install-WindowsFeature DHCP -IncludeManagementTools # install DHCP
    Add-DhcpServerInDC -DnsName controller.local -IPAddress 192.168.178.1 # authorize DHCP
    Add-DhcpServerv4Scope -Name "scope1" -StartRange 192.168.178.1 -EndRange 192.168.178.254 -SubnetMask 255.255.255.0 # create DHCP scope
    New-ADOrganizationalUnit -Name "FiSi" # create OU
    New-ADUser -Name "Rainer Winkler" -GivenName "Rainer" -Surname "Winkler" -SamAccountName "rwinkler" -Path "OU=FiSi,DC=controller,DC=local" -AccountPassword (ConvertTo-SecureString "Pa$$w0rd" -AsPlainText -Force) -Enabled $true # create user
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 # enable RDP
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "rwinkler" # add user to RDP group
} else {
    Set-SConfig -AutoLaunch $false  # disable Sconfig auto launch
    Rename-Computer -NewName "winServer"    # rename computer
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6     # disable IPv6
    New-NetIPAddress –IPAddress 192.168.178.1 -DefaultGateway 192.168.178.0 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex    # set static IP
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.178.1    # force DNS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 4 # auto updates
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools   # install AD DS
    Install-ADDSForest -DomainName controller.local -InstallDNS     # setup Domain and Install DNS

    # Restart and continue above
    New-Item "C:\rcount.txt" -ItemType File -Value "1" # create lockfile
    $scriptPath = $MyInvocation.MyCommand.Path
    $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKeyPath -Name "WinServerInstallScript" -Value $scriptPath
    shutdown /r /t 0
}