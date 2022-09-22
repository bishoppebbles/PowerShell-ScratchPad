# Pull computer objects listed in the Directory
$computers = (Get-ADComputer -Filter *).Name

# Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
$sess = New-PSSessionOption -NoMachineProfile

# Local Administrators group membership
Invoke-Command -ComputerName $computers -ScriptBlock {Get-LocalGroupMember Administrators} -SessionOption $sess | 
	Export-Csv -Path local_admins_group.csv -NoTypeInformation

# Local user accounts
Invoke-Command -ComputerName $computers -ScriptBlock {Get-LocalUser} -SessionOption $sess | 
	Export-Csv -Path local_users.csv -NoTypeInformation

# Processes
Invoke-Command -ComputerName $computers -ScriptBlock {Get-Process | Select-Object Name,Id,Path,Company,Description,ProductVersion,StartTime} -SessionOption $sess |
	Export-Csv -Path processes.csv -NoTypeInformation

# Scheduled tasks
Invoke-Command -ComputerName $computers -ScriptBlock {Get-ScheduledTask} -SessionOption $sess | 
	Export-Csv -Path scheduled_tasks.csv -NoTypeInformation

# Services
Invoke-Command -ComputerName $computers -ScriptBlock {Get-Service} -SessionOption $sess | 
	Export-Csv -Path services.csv -NoTypeInformation

# Downloads, Documents, and Desktop files
Invoke-Command -ComputerName $computers -ScriptBlock {Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse} -SessionOption $sess | 
	Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} |
	Export-Csv -Path files.csv -NoTypeInformation

# 32/64 bit Programs
Invoke-Command -ComputerName $computers -ScriptBlock {Get-ChildItem -Path 'C:\Program Files','C:\Program Files (x86)'} -SessionOption $sess | 
	Select-Object Name,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} -SessionOption $sess |
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

Invoke-Command -ComputerName $computers -ScriptBlock ${function:netConnects} -SessionOption $sess |
    Export-Csv -Path .\net.csv -Append -NoTypeInformation
