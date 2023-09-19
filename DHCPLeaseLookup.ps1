$dhcp = '<dhcp_server>'
Get-DHCPServerv4Scope -ComputerName $dhcp | 
  Get-DHCPServerv4Lease -ComputerName $dhcp -AllLeases | 
  Export-Csv dhcp_leases.csv -NoTypeInformation
