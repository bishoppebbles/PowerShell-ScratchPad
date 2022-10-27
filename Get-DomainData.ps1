<#
Enable PS Remoting via Group Policy

Enable the WinRM service (set IPv4/IPv6 filters to all (*))
	Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM

Set the WS-Management service to automatic startup
	Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)

Allow Windows Remote Management in the Firewall
	Navigate to the following folder in the Group Policy Management Console (GPMC), right-click Inbound Rules, and click New Rule.

		Computer Configuration > Policies > Windows Settings > Security Settings > Windows (Defender) Firewall with Advanced Security

		In the Predefined field, select Windows Remote Management and then follow the wizard to add the new firewall rule.
#>

$distinguisedName = (Get-ADDomain).DistinguishedName

<#
Functions
#>

function netConnects() {
    $hashtable = @{}
    $date = Get-Date -Format "MM/dd/yyyy"
    $time = Get-Date -Format "HH:mm"
        
    Get-Process | 
        ForEach-Object { 
            $hashtable.$($_.Id) = $_.ProcessName
        }

    Get-NetTCPConnection -State Listen,Established |
        Select-Object @{Name = "Date"; Expression = {$date}},@{Name = "Time"; Expression = {$time}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{Name = "ProcessName"; Expression = {$hashtable[[int]$_.OwningProcess]}}
}

function localUsers() {
    try {
        Get-LocalUser
    } catch [System.Management.Automation.RuntimeException] {
        # Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -Property * | Select-Object Name,Domain,SID,PasswordExpires,Disabled,Lockout,PasswordRequired,PasswordChangeable,Description
        
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
        $Users = $adsi.Children | Where-Object {$_.SchemaClassName  -eq 'user'}

        $date = Get-Date

        $Users | ForEach-Object {
            Write-Output "$($_.Name.value)`t$($date.AddSeconds(-1 * $_.PasswordAge.value))`t$((New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value)"
        }
    }
}

<#
(New-Object System.Security.Principal.SecurityIdentifier($Users[0].objectSid.value,0)).Value

# Function code source and credit to Boe Prox
# Reporting on Local Accounts Using PowerShell 
# https://mcpmag.com/articles/2015/04/15/reporting-on-local-accounts.aspx

Function Convert-UserFlag  {
    Param ($UserFlag)

    $List = New-Object System.Collections.ArrayList

    Switch  ($UserFlag) {
        ($UserFlag -bor 0x0001)     {[void]$List.Add('SCRIPT')}
        ($UserFlag -bor 0x0002)     {[void]$List.Add('ACCOUNTDISABLE')}
        ($UserFlag -bor 0x0008)     {[void]$List.Add('HOMEDIR_REQUIRED')}
        ($UserFlag -bor 0x0010)     {[void]$List.Add('LOCKOUT')}
        ($UserFlag -bor 0x0020)     {[void]$List.Add('PASSWD_NOTREQD')}
        ($UserFlag -bor 0x0040)     {[void]$List.Add('PASSWD_CANT_CHANGE')}
        ($UserFlag -bor 0x0080)     {[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')}
        ($UserFlag -bor 0x0100)     {[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')}
        ($UserFlag -bor 0x0200)     {[void]$List.Add('NORMAL_ACCOUNT')}
        ($UserFlag -bor 0x0800)     {[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')}
        ($UserFlag -bor 0x1000)     {[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')}
        ($UserFlag -bor 0x2000)     {[void]$List.Add('SERVER_TRUST_ACCOUNT')}
        ($UserFlag -bor 0x10000)    {[void]$List.Add('DONT_EXPIRE_PASSWORD')}
        ($UserFlag -bor 0x20000)    {[void]$List.Add('MNS_LOGON_ACCOUNT')}
        ($UserFlag -bor 0x40000)    {[void]$List.Add('SMARTCARD_REQUIRED')}
        ($UserFlag -bor 0x80000)    {[void]$List.Add('TRUSTED_FOR_DELEGATION')}
        ($UserFlag -bor 0x100000)   {[void]$List.Add('NOT_DELEGATED')}
        ($UserFlag -bor 0x200000)   {[void]$List.Add('USE_DES_KEY_ONLY')}
        ($UserFlag -bor 0x400000)   {[void]$List.Add('DONT_REQ_PREAUTH')}
        ($UserFlag -bor 0x800000)   {[void]$List.Add('PASSWORD_EXPIRED')}
        ($UserFlag -bor 0x1000000)  {[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')}
        ($UserFlag -bor 0x04000000) {[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')}
    }

    $List -join ', '
}
#>


<#
    # ADSI for getting local group membership
    # https://mcpmag.com/articles/2015/06/18/reporting-on-local-groups.aspx
    # https://gist.github.com/jdhitsolutions/a37a8a34b5b99bd3e132
    Function  ConvertTo-SID {
        Param([byte[]]$BinarySID)
            
        (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
    }

    Function  Get-LocalGroupMember {
        Param($Group)
            
        $group.Invoke('members') | ForEach-Object {
            @{
                $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) =
                $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)
            }
            #$_.GetType().InvokeMember("ADSPath", 'GetProperty', $null, $_, $null)
        }
    }

    $adsi  = [ADSI]"WinNT://$env:COMPUTERNAME"
    $groups  = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'group'}

    if ($groups) {
        $groupMembers = $groups | 
            ForEach-Object {
                Get-LocalGroupMember -Group $_
                [pscustomobject]@{
                    Computername = $Computer
                    Name         = $_.Name[0]
                    Members      = (Get-LocalGroupMember -Group $_)
                    SID          = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
                }
            } | Where-Object {$_.Members -notlike ''}
    }


    foreach($group in $groupMembers) {
        foreach($member in $group.Members) {
            [pscustomobject]@{
                Computername = $group.ComputerName
                Name         = $group.Name
                Members      = $($member.Keys)
                Class        = $($member.Values)
                SID          = $group.SID
            }
        }
    }
#>



<#
Pull remote system data
#>

# Pull Windows computer objects listed in the Directory
$computers = Get-ADComputer -Filter * -SearchBase $distinguisedName -Properties OperatingSystem,LastLogonDate |
                Where-Object {$_.OperatingSystem -like "Windows*"}

# Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
$sessionOpt = New-PSSessionOption -NoMachineProfile

$Error.Clear()
$failedPSSessions = New-Object System.Collections.ArrayList

# Create reusable PS Sessions
$sessions = New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt -ErrorAction SilentlyContinue

if ($Error.Count -gt 0) {    
    Write-Output "PowerShell Remoting Session Failures:"

    $Error |
        Where-Object {$_.Exception -ne $null} |
            ForEach-Object {
                if ($_.Exception.GetType().FullName -like "System.Management.Automation.Remoting.PSRemotingTransportException") {
                    if ($_.ErrorDetails -match "\[(.*)\]") {
                        $failedPSSessions.Add($Matches[1]) | Out-Null
                    }
                }
            }
    $failedPSSessions
}

<#
foreach($computer in $failedSessions) {
    $cimSessOption = New-CimSessionOption -Protocol Dcom
    $cimSession = New-CimSession -ComputerName $computer -SessionOption $cimSessOption
    Invoke-CimMethod -ClassName 'Win32_Process' -MethodName 'Create' -CimSession $cimSession -Arguments @{CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"}
}
#>

# Local Administrators group membership
# System.Management.Automation.RemoteException
# Source: Ben Baird's Get-LocalGroupMembers (8/12/2011) on Microsoft's TechNet (page no longer valid)
# (Get-CimInstance -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'`"").PartComponent.Name
Invoke-Command -Session $sessions -ScriptBlock {Get-LocalGroupMember Administrators | Select-Object PSComputerName,Name,SID,PrincipalSource,ObjectClass} | 
	Export-Csv -Path local_admins_group.csv -NoTypeInformation

# Local user accounts
Invoke-Command -Session $sessions -ScriptBlock ${function:localUsers} | 
	Export-Csv -Path local_users.csv -NoTypeInformation

# Processes
Invoke-Command -Session $sessions -ScriptBlock {Get-Process -IncludeUserName | Select-Object Name,Id,Path,UserName,Company,Description,ProductVersion,StartTime} |
	Export-Csv -Path processes.csv -NoTypeInformation

# Scheduled tasks
Invoke-Command -Session $sessions -ScriptBlock {Get-ScheduledTask} | 
	Export-Csv -Path scheduled_tasks.csv -NoTypeInformation

# Services
Invoke-Command -Session $sessions -ScriptBlock {Get-Service} | 
	Export-Csv -Path services.csv -NoTypeInformation

# Downloads, Documents, and Desktop files
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse | Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} |
	Export-Csv -Path files.csv -NoTypeInformation

# 32/64 bit Programs
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Program Files','C:\Program Files (x86)' | Select-Object Name,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} |
	Export-Csv -Path programs.csv -NoTypeInformation

# Network connections
Invoke-Command -Session $sessions -ScriptBlock ${function:netConnects} |
    Export-Csv -Path .\net.csv -Append -NoTypeInformation
    
Remove-PSSession -Session $sessions


<#
Pull data from the local system and append to the existing CSV files
#>

# Local Administrators group membership
Get-LocalGroupMember Administrators |
	Export-Csv -Path local_admins_group.csv -Append -NoTypeInformation

# Local user accounts
Get-LocalUser |
	Export-Csv -Path local_users.csv -Append -NoTypeInformation

# Processes
Get-Process -IncludeUserName |
    Select-Object Name,Id,Path,UserName,Company,Description,ProductVersion,StartTime |
	Export-Csv -Path processes.csv -Append -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask |
	Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation

# Services
Get-Service |
	Export-Csv -Path services.csv -Append -NoTypeInformation

# Downloads, Documents, and Desktop files
Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse |
    Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
	Export-Csv -Path files.csv -Append -NoTypeInformation

# 32/64 bit Programs
Get-ChildItem -Path 'C:\Program Files','C:\Program Files (x86)' |
    Select-Object Name,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
	Export-Csv -Path programs.csv -Append -NoTypeInformation

netConnects |
    Export-Csv -Path .\net.csv -Append -NoTypeInformation


<#
Pull Active Directory datasets
#>

# Get domain user account information
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired -SearchBase $distinguisedName |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get domain computer account info
Get-ADComputer -Filter * -Properties DistinguishedName,Enabled,IPv4Address,LastLogonDate,Name,OperatingSystem,SamAccountName -SearchBase $distinguisedName |
	Export-Csv -Path domain_computers.csv -NoTypeInformation

# Get privileged domain account group memberships
$adminMemberOf = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * -Properties * -SearchBase $distinguisedName

foreach($group in $groups) {
    Get-ADGroupMember -Identity $group.SamAccountName -Recursive | 
	    Where-Object {
	        ($_.objectClass -like "user") -and 
		    ($_.SamAccountName -like "*adm*" -or $_.SamAccountName -like "*admin*" -or $_.SamAccountName -like "*isso*")
	    } |
        ForEach-Object {
            $adminMemberOf.Add([PSCustomObject]@{
                UserSamAccountName  = $_.SamAccountName
                UserDN              = $_.distinguishedName
                UserName            = $_.name
                GroupSamAccountName = $group.SamAccountName
                GroupDN             = $group.DistinguishedName
            }) | Out-Null
        }
}

$adminMemberOf | Export-Csv -Path domain_admins.csv -NoTypeInformation