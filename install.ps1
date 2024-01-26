# Script to install and configure ADDS, DHCP and DNS on Windows Server 2022
# execute by running "irm https://raw.githubusercontent.com/Optinux/scripts-stuff/main/install.ps1 > C:\install.ps1 ; iex C:\install.ps1" or by running "irm install.optinux.me | iex"
# Made by github.com/Optinux

New-Item "C:\rcount.txt" -ItemType File -Value "0" # create lockfile
$scriptPath = "powershell.exe C:\install.ps1" # path to script including commands
$ADDSPWD = ConvertTo-SecureString "Pa$$w0rd" -AsPlainText -Force # set password for AD DS 
$filePath = "C:\rcount.txt"
$fileContent = Get-Content -Path $filePath
switch ($fileContent) 
{
  0 {
    Set-SConfig -AutoLaunch $false  # disable Sconfig auto launch
    Rename-Computer -NewName "winServer"    # rename computer
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6     # disable IPv6
    New-NetIPAddress –IPAddress 192.168.178.1 -DefaultGateway 192.168.178.0 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex    # set static IP
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.178.1    # force DNS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 4 # auto updates
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools   # install AD DS
    
    $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" # set script to run on next boot
    Set-ItemProperty -Path $runKeyPath -Name "WinServerInstallScript" -Value $scriptPath
    Remove-Item $filePath # remove lockfile
    New-Item "C:\rcount.txt" -ItemType File -Value "1" # update lockfile
    shutdown /r /t 0
    }

  1 {
    Write-Host "First Reboot succeeded, continuing with installation"
    Remove-Item $filePath # remove lockfile
    New-Item "C:\rcount.txt" -ItemType File -Value "2" # update lockfile
    $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" # set script to run on next boot
    Set-ItemProperty -Path $runKeyPath -Name "WinServerInstallScript" -Value $scriptPath

    Install-ADDSForest -DomainName controller.local -InstallDNS -SafeModeAdministratorPassword $ADDSPWD -Confirm -Force    # setup Domain and Install DNS
    shutdown /r /t 0
    }
  
  2 {
    Write-Host "Second Reboot succeeded, continuing with installation"
    Remove-Item $filePath # remove lockfile

    Install-WindowsFeature DHCP -IncludeManagementTools # install DHCP
    Add-DhcpServerInDC -DnsName controller.local -IPAddress 192.168.178.1 # authorize DHCP
    Add-DhcpServerv4Scope -Name "scope1" -StartRange 192.168.178.1 -EndRange 192.168.178.254 -SubnetMask 255.255.255.0 # create DHCP scope
    New-ADOrganizationalUnit -Name "FiSi" # create OU
    New-ADUser -Name "Rainer Winkler" -GivenName "Rainer" -Surname "Winkler" -SamAccountName "rwinkler" -Path "OU=FiSi,DC=controller,DC=local" -AccountPassword (ConvertTo-SecureString "Pa$$w0rd" -AsPlainText -Force) -Enabled $true # create user
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 # enable RDP
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "rwinkler" # add user to RDP group
    Write-Host "Installation finished!"

    Remove-Item $scriptPath -Force # remove script
    }
}
