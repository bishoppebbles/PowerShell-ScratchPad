# get local system info
$adapterName = 'Ethernet'
$localHost   = $env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN.ToLower()
$localIp     = (Get-NetIPAddress -InterfaceAlias $adapterName).IPAddress
$localMac    = (Get-NetAdapter -Name $adapterName).MacAddress

# determine the /24 subnet (if you're not on a /24 you 
$baseIp = $localIp.Split('.')[0..2] -join '.'
$slash24 = 1..254

foreach($ip in $slash24) {
    Test-Connection $($baseIp + '.' + $ip) -Count 1 -AsJob
}

(Get-NetNeighbor -State Reachable,Stale).Count

# populate the local arp cache with IP-MAC mappings
while(Get-Job -State Running) {
    Write-Output "Jobs are still running... sleeping 5 seconds."
    Start-Sleep -Seconds 5
}

Get-Job | Remove-Job

(Get-NetNeighbor -State Reachable,Stale).Count

# print local system info
[pscustomobject]@{
    hostName   = $localHost
    ipAddress  = $localIp
    macAddress = $localMac
}

Get-NetNeighbor -State Reachable,Stale | 
    ForEach-Object {
        Start-Job -ScriptBlock {Resolve-DnsName $_.IPAddress -QuickTimeout -ErrorAction SilentlyContinue}
    }

while(Get-Job -State Running) {
    Write-Output "DNS is still running... sleeping five seconds."
    Start-Sleep -Seconds 5
}

# (Get-Job | Receive-Job).Name.Split('.')[3..0] -join '.'

Get-NetNeighbor -State Reachable,Stale | 
    ForEach-Object {
        $dns = Resolve-DnsName $_.IPAddress -QuickTimeout -ErrorAction SilentlyContinue

        [pscustomobject]@{
            hostName   = $dns.NameHost
            ipAddress  = $_.IPAddress
            macAddress = $_.LinkLayerAddress
        }
    } 
