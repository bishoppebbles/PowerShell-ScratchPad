<#
Steps to enable PS Remoting via Group Policy

Enable the WinRM service (set IPv4/IPv6 filters to all (*))
	Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM

Set the WS-Management service to automatic startup
	Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)

Allow Windows Remote Management in the Firewall
	Navigate to the following folder in the Group Policy Management Console (GPMC), right-click Inbound Rules, and click New Rule.

		Computer Configuration > Policies > Windows Settings > Security Settings > Windows (Defender) Firewall with Advanced Security

		In the Predefined field, select Windows Remote Management and then follow the wizard to add the new firewall rule.
#>

$distinguishedName = (Get-ADDomain).DistinguishedName

<#
Functions
#>

# Get system TCP session and related process information
function netConnects() {
    $hashtable = @{}
    $date = Get-Date -Format "MM/dd/yyyy"
    $time = Get-Date -Format "HH:mm"
    
    # used to map to the process name to the TCP connection process ID
    Get-Process | 
        ForEach-Object { 
            $hashtable.$($_.Id) = $_.ProcessName
        }

    Get-NetTCPConnection -State Listen,Established |
        Select-Object @{Name='Date'; Expression={$date}},@{Name='Time'; Expression={$time}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{Name='ProcessName'; Expression={$hashtable[[int]$_.OwningProcess]}}
}


# Try to first get local user account info using the PS cmdlet but if that is unavailable use WMI to get the data
function getLocalUsers() {
    try {
        Get-LocalUser |
            Select-Object Name,SID,Enabled,PasswordRequired,@{Name='PasswordChangeable'; Expression={$_.UserMayChangePassword}},PrincipalSource,Description,PasswordLastSet,LastLogon
    } catch [System.Management.Automation.RuntimeException] {       
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -Property * | 
            Select-Object Name,SID,@{Name='Enabled'; Expression={if([bool]$_.Disabled) {'False'} else {'True'}}},PasswordRequired,PasswordChangeable,@{Name='PrincipalSource';Expression={if([bool]$_.LocalAccount) {'Local'}}},Description,@{Name='PasswordLastSet'; Expression={'Unavailable'}},@{Name='LastLogon'; Expression={'Unavailable'}}
    }
}


# Try to first get the group membership of all local groups using PS cmdlets but if that is unavailable use ADSI
# note: attempts to use the CIM WMI cmdlets would not work in my domain environment locally or remotely and it's unknown why
#   1) Get-CimInstance -Query "Associators of {Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'} where Role=GroupComponent"
#   2) Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators'" | Get-CimAssociatedInstance -Association Win32_GroupUser
function getLocalGroupMembers() {
    try {
        # get all local groups
        $groups = Get-LocalGroup

        # get the membership for all local groups
	    foreach ($group in $groups) {
    	    Get-LocalGroupMember $group | 
                ForEach-Object {
                    [pscustomobject]@{
                        GroupName       = $group.Name
                        Name            = $_.Name.split('\')[1]
                        Domain          = $_.Name.split('\')[0]
                        SID             = $_.SID
                        PrincipalSource = $_.PrincipalSource
                        ObjectClass     = $_.ObjectClass
                    } 
                }
        }
    
    # run if the Get-Local* cmdlets are not installed on the remote systems
    } catch [System.Management.Automation.RuntimeException] {
        
        # convert the provided value to a readable SID
        function ConvertTo-SID {
            Param([byte[]]$BinarySID)
            
            (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
        }

        # get and parse the group member data points of interest
        function localGroupMember {
            Param($Group)
            
            $group.Invoke('members') | ForEach-Object {
                # parse the ADSPath to get the domain and determine if it's a local object or from AD
                $_.GetType().InvokeMember("ADSPath", 'GetProperty', $null, $_, $null) -match "WinNT:\/\/(\w+)\/(.+)\/" | Out-Null
            
                if($Matches.Count -gt 2) {
                    $domain = $Matches[2]
                    $source = 'Local'
                    $Matches.Clear()
                } elseif($Matches) {
                    $_.GetType().InvokeMember("ADSPath", 'GetProperty', $null, $_, $null) -match "WinNT:\/\/(\w+)\/" | Out-Null
                    $domain = $Matches[1]
                    $source = 'ActiveDirectory'
                    $Matches.Clear()
                }        

                [pscustomobject]@{
                    Name            = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                    ObjectClass     = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)    
                    SID             = ConvertTo-SID $_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null)
                    Domain          = $domain
                    PrincipalSource = $source
                }
            }
        }

        # get local groups using ADSI
        $adsi   = [ADSI]"WinNT://$env:COMPUTERNAME"
        $groups = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'group'}

        # get group members for each local group
        if ($groups) {
            $groupMembers = $groups | 
                ForEach-Object {
                    [pscustomobject]@{
                        Computername = $env:COMPUTERNAME
                        GroupName    = $_.Name[0]
                        GroupMembers = (localGroupMember -Group $_)
                    }
                # ignore groups with no members
                } | Where-Object {$_.GroupMembers -notlike ''}
        }

        # output the combined group and individual group member data
        foreach($group in $groupMembers) {
            foreach($member in $group.GroupMembers) {
                [pscustomobject]@{
                    #Computername    = $group.ComputerName
                    GroupName       = $group.GroupName
                    Name            = $member.Name
                    Domain          = $member.Domain
                    SID             = $member.SID
                    PrincipalSource = $member.PrincipalSource
                    ObjectClass     = $member.ObjectClass            
                }
            }
        }
    }
}


<#
Build PowerShell sessions for query reuse
#>

# Pull Windows computer objects listed in the Directory
$computers = Get-ADComputer -Filter * -SearchBase $distinguishedName -Properties OperatingSystem,LastLogonDate |
                Where-Object {$_.OperatingSystem -like "Windows*"}

# Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
$sessionOpt = New-PSSessionOption -NoMachineProfile

# Create reusable PS Sessions
$sessions = New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt


<#
foreach($computer in $failedSessions) {
    $cimSessOption = New-CimSessionOption -Protocol Dcom
    $cimSession = New-CimSession -ComputerName $computer -SessionOption $cimSessOption
    Invoke-CimMethod -ClassName 'Win32_Process' -MethodName 'Create' -CimSession $cimSession -Arguments @{CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"}
}
#>


<#
Pull remote system data
#>

# Local Administrators group membership
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalGroupMembers} |
    Export-Csv -Path local_admins_group.csv -NoTypeInformation

# Local user accounts
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalUsers} | 
	Export-Csv -Path local_users.csv -NoTypeInformation

<#
# Check running executables for malware via VirusTotal
# This query uses a 15 second timeout to ensure only 4 queries are submitted a minute and only unique hashes are queried

$A = $( foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}) |Sort-Object| Get-Unique -AsString; foreach ($process in $A) {Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body @{ resource =($process); apikey = "[VTAPIKey]"};Start-Sleep -Seconds 15;} 
#>

# Processes
Invoke-Command -Session $sessions -ScriptBlock {Get-Process -IncludeUserName | Select-Object Name,Id,Path,UserName,Company,Description,ProductVersion,StartTime} |
	Export-Csv -Path processes.csv -NoTypeInformation

# Scheduled tasks
Invoke-Command -Session $sessions -ScriptBlock {Get-ScheduledTask | Select-Object TaskName,State,Author,TaskPath,Description} | 
	Export-Csv -Path scheduled_tasks.csv -NoTypeInformation

# Services
Invoke-Command -Session $sessions -ScriptBlock {Get-Service | Select-Object Name,DisplayName,Status,StartType,ServiceType} |
	Export-Csv -Path services.csv -NoTypeInformation

# Downloads, Documents, and Desktop files
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse | Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} |
	Export-Csv -Path files.csv -NoTypeInformation

# 64 bit programs
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Program Files' | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}} |
	Export-Csv -Path programs.csv -NoTypeInformation

# 32 bit programs
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Program Files (x86)' | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}} |
	Export-Csv -Path programs.csv -NoTypeInformation

# Network connections
Invoke-Command -Session $sessions -ScriptBlock ${function:netConnects} |
    Export-Csv -Path net.csv -Append -NoTypeInformation
    
Remove-PSSession -Session $sessions


<#
Pull data from the local system and append to the existing CSV files
#>

# Local Administrators group membership
getlocalGroupMembers |
	Export-Csv -Path local_admins_group.csv -Append -NoTypeInformation

# Local user accounts
getLocalUsers |
	Export-Csv -Path local_users.csv -Append -NoTypeInformation

# Processes
# Check if the local session is running with elevated privileges
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $localProcesses = Get-Process -IncludeUserName
} else {
    $localProcesses = Get-Process
}

$localProcesses |
    Select-Object Name,Id,Path,UserName,Company,Description,ProductVersion,StartTime |
	Export-Csv -Path processes.csv -Append -NoTypeInformation

# Scheduled tasks
Get-ScheduledTask |
    Select-Object TaskName,State,Author,TaskPath,Description |
	Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation

# Services
Get-Service |
    Select-Object Name,DisplayName,Status,StartType,ServiceType |
	Export-Csv -Path services.csv -Append -NoTypeInformation

# Downloads, Documents, and Desktop files
Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse |
    Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
	Export-Csv -Path files.csv -Append -NoTypeInformation

# 64 bit programs
Get-ChildItem -Path 'C:\Program Files' |
    Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}} |
	Export-Csv -Path programs.csv -Append -NoTypeInformation

# 32 bit programs
Get-ChildItem -Path 'C:\Program Files (x86)' |
    Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}} |
	Export-Csv -Path programs.csv -Append -NoTypeInformation

# Network connections
netConnects |
    Export-Csv -Path net.csv -Append -NoTypeInformation


<#
Pull Active Directory datasets
#>

# Get domain user account information
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired -SearchBase $distinguishedName |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get domain computer account info
Get-ADComputer -Filter * -Properties DistinguishedName,Enabled,IPv4Address,LastLogonDate,Name,OperatingSystem,SamAccountName -SearchBase $distinguishedName |
	Export-Csv -Path domain_computers.csv -NoTypeInformation

# Get privileged domain account group memberships
$adminMemberOf = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * -Properties * -SearchBase $distinguishedName

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