# copy/paste your block of IPs (e.g., from nmap)
$ips = ‘<ip_list>’

# or input them from a text file
$ips = Get-Content <ips.txt>

# parse the IPs and HTTP/S browse to each one with Chrome
Start-Process chrome ((Select-String -InputObject $ips -Pattern '\d{1,3}(\.\d{1,3}){3}' -AllMatches).Matches.Value  | Select-Object -Unique)

# DNS lookup your block of IPs
(Select-String -InputObject $ips -Pattern '\d{1,3}(\.\d{1,3}){3}' -AllMatches).Matches.Value | Select-Object -Unique | Resolve-DnsName
