$searchBase = 'ou=location,dc=my,dc=domain,dc=com'
$comp = New-Object System.Collections.ArrayList
$computers = Get-ADComputer -Filter * -SearchBase $searchBase

$computers | Where-Object {$_.DNSHostName -notlike ""} | ForEach-Object {$comp.Add($_.DNSHostName)} | Out-Null

$output = 
    try {
        Invoke-Command -ComputerName $comp -ErrorAction Stop -ScriptBlock {
            Get-CimInstance -ClassName Win32_Process | 
                Select-Object Name,ProcessId,ParentProcessId,SessionId }
    } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        Write-Host "WinRM communication failed"
    }

$output | Format-Table Name,ProcessId,ParentProcessId,SessionId,PSComputerName -AutoSize