$searchBase = "ou=location,dc=my,dc=domain,dc=com"
$dc = 'domainController.domain.com'
$distGroups = Get-ADGroup -Filter "GroupCategory -eq 'Distribution'" -SearchBase $searchBase -Server $dc
foreach($group in $distGroups) {
    Write-Output $group.SamAccountName
    Get-ADGroupMember $group -Recursive | Select-Object SamAccountName | Format-Table -HideTableHeaders
    Write-Output "`n"
}