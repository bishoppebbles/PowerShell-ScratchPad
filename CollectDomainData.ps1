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

# Pull computer objects listed in the Directory
$computers = (Get-ADComputer -Filter *).Name

# Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
$sessionOpt = New-PSSessionOption -NoMachineProfile

# Create reusable PS Sessions
$sessions = New-PSSession -ComputerName $computers -SessionOption $sessionOpt

# Local Administrators group membership
Invoke-Command -Session $sessions -ScriptBlock {Get-LocalGroupMember Administrators} | 
	Export-Csv -Path local_admins_group.csv -NoTypeInformation

# Local user accounts
Invoke-Command -Session $sessions -ScriptBlock {Get-LocalUser} | 
	Export-Csv -Path local_users.csv -NoTypeInformation

# Processes
Invoke-Command -Session $sessions -ScriptBlock {Get-Process | Select-Object Name,Id,Path,Company,Description,ProductVersion,StartTime} |
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

Invoke-Command -Session $sessions -ScriptBlock ${function:netConnects} |
    Export-Csv -Path .\net.csv -Append -NoTypeInformation
    
Remove-PSSession -Session $sessions

# Get domain user account information
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get domain computer account info
Get-ADComputer -Filter * -Properties DistinguishedName,Enabled,IPv4Address,LastLogonDate,Name,OperatingSystem,SamAccountName |
	Export-Csv -Path domain_computers.csv -NoTypeInformation

# Get privileged domain account group memberships
$adminMemberOf = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * -Properties *

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
