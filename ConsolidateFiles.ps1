# cd to the top level container directory of interest then run
# for each directory recursively move all child files to the directory root
# then recursively delete all the existing child directories

$emailAddresses = Get-ChildItem
foreach($email in $emailAddresses) {
    Get-ChildItem $email -File -Recurse | Move-Item -Destination $email.FullName -Force  # -Force will overwrite a file with the same name if it already exists
    Get-ChildItem $email -Directory | Remove-Item -Recurse
}


# consolidate copies from an archive of the lastest running config for all switches at a given location

$date = [datetime]"10/19/2019"

Get-ChildItem \\<network_share_path>\Config-Archive\*location_root_name* | 
    ForEach-Object {Get-ChildItem $_.FullName | 
    	Where-Object {$_.LastWriteTime -gt $date}
    } | 
    ForEach-Object {Get-ChildItem "$($_.FullName)\*Running*"} | 
	Copy-Item 
