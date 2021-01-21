# locate AD accounts that are not assigned to the given location; write the output to a text file

$outfile = 'output.txt'
$domain  = 'domain'
$location= 'location'

Get-ADGroup -Filter * -SearchBase "ou=$location,dc=$domain,dc=domain2,dc=com" | 
    ForEach-Object {

        $group = Get-ADGroupMember $_ | Where-Object {$_ -notlike "*$location*"}
        
        if($group.length -gt 0) {
            Add-Content -Path $outfile -Value "$_"

            foreach($member in $group) { 
                Add-Content -Path $outfile -Value "$member"
            }
            # add newlines to each section
            Add-Content -Path $outfile -Value ""
        }
    }
