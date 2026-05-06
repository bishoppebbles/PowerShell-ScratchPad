$netAccountsLocal = net accounts
$resultsLocal = [ordered]@{}

# Parse each line based on the colon delimiter
switch -Regex ($netAccountsLocal) {
    '(.+?):\s+(.+)' {
        $key = "L_" + ((Get-Culture).TextInfo.ToTitleCase(($matches[1].Trim()).ToLower()).Replace(" ","") -replace 'Password','Pw' -replace 'Minutes','Min')
        $value = $matches[2].Trim()
        $resultsLocal[$key] = $value
    }
}

# Convert the hashtable to a standard PowerShell object
[PSCustomObject]$resultsLocal

if((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    $netAccountsDomain = net accounts /domain
    $resultsDomain = [ordered]@{}

    # Parse each line based on the colon delimiter
    switch -Regex ($netAccountsDomain) {
        '(.+?):\s+(.+)' {
            $key = "D_" + ((Get-Culture).TextInfo.ToTitleCase(($matches[1].Trim()).ToLower()).Replace(" ","") -replace 'Password','Pw' -replace 'Minutes','Min')
            $value = $matches[2].Trim()
            $resultsDomain[$key] = $value
        }
    }

    # Convert the hashtable to a standard PowerShell object
    [PSCustomObject]$resultsDomain
}
