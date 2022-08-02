# run every $interval seconds for New-TimeSpan length
# to run infinitely change loop to while(1 -eq 1)

$interval = 30
$timer = New-TimeSpan -Minutes 60
$clock = [diagnostics.stopwatch]::StartNew()


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

while($clock.elapsed -lt $timer){
#while(1 -eq 1) {
    Invoke-Command -ComputerName <system> -ScriptBlock ${function:netConnects} |
        Export-Csv -Path .\output.csv -Append -NoTypeInformation
    Start-Sleep -Seconds $interval
}
