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
