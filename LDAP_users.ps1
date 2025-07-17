$list = Get-Content .\users_list.txt
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# use the AD PowerShell module if available otherwise query based on LDAP
if(Get-Module ActiveDirectory) {
    $output = foreach($entry in $list) {
        $escaped = $entry -replace "'","''"
        $info = Get-ADUser -Filter "DisplayName -like '$escaped'" -Server state.sbu -Properties DisplayName,Title,Department,Description
        [PSCustomObject]@{
            DisplayName    = $info.DisplayName
            Title          = $info.Title
            Department     = $info.Department
            Description    = $info.Description
            SamAccountName = $info.SamAccountName
        }
    } 
} else {
    $Domain = 'domain.com'
    $OUDistinguishedName = 'OU=location,DC=domain,DC=com'

    $output = foreach($entry in $list) {
        $searcher = [adsiSearcher]"(&(samAccountType=805306368)(DisplayName=$entry))"
        $searcher.SearchRoot = [ADSI]"LDAP://$Domain/$OUDistinguishedName"
        $info = $searcher.FindOne()

        [PSCustomObject]@{
            DisplayName    = $($info.Properties.displayname)
            Title          = $($info.Properties.title)
            Department     = $($info.Properties.department)
            Description    = $($info.Properties.description)
            SamAccountName = $($info.Properties.samaccountname)
        }
    }
}

$output | Export-Csv output.csv -NoTypeInformation