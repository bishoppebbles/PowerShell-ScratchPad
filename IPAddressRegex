# input your block of IPs (e.g., from nmap)
$ips = ‘<ip_list>’

# parse the IPs and HTTP/S browse to each one with Chrome
Start-Process chrome ((Select-String -InputObject $ips -Pattern '\d{1,3}(\.\d{1,3}){3}' -AllMatches).Matches.Value)

# DNS lookup your block of IPs
(Select-String -InputObject $ips -Pattern '\d{1,3}(\.\d{1,3}){3}' -AllMatches).Matches.Value | Resolve-DnsName
