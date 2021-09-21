$urls        = @{}   # hash table to store and track downloaded links
$tempUrls    = @{}   # hash table to temporarily store link data
$pageMapping = @{}   # hash table to map the original link path to the new link name
$count       = 100;  # counter variable to easily name and track new file names
$more        = $true # while loop control variable
$tempStr     = [System.Text.StringBuilder]::new()  # temp string builder to rebuild html files with the updated link path
$baseUrl     = 'http://website.com'  # note: this is not the original URL
$seedSite    = 'http://website.com/schemes/path/80a2354fa0510d9ecf99fa293f4cdf6a795d6d75325f33bfdd835fbe500ae33d51e2c05cb206ec1287eee8e95c99be81d6a974998a1802ec4bf70e5aeb85086bf684d3846726fb144ac5c048a1516760f23ceb194c'
$linkRegex   = '(\/schemes\/path\/[0123456789abcdef]{170,})'  # regex to match the basePath path
$baseDoc    = '80a2354fa0510d9ecf99fa293f4cdf6a795d6d75325f33bfdd835fbe500ae33d51e2c05cb206ec1287eee8e95c99be81d6a974998a1802ec4bf70e5aeb85086bf684d3846726fb144ac5c048a1516760f23ceb194c'

Write-Output 'STATUS: Starting downloads'

# get the base url
# basic parsing option is required to NOT use the IE parsing engine
$site = Invoke-WebRequest $seedSite -UseBasicParsing
$site.Content | Out-File 'BeginHere.html'

# seed the initial hash table with urls
$site.Links | Where-Object {$_.href -like "*$($baseDoc)*"} | 
    ForEach-Object {
        if (-not $urls.ContainsKey($_.href)) {
            $urls.Add($_.href, $false)
            $pageMapping.Add($_.href, ('Toyota' + $count + '.html'))
            $count+=1
        }
}

# query for more urls until no new ones are found
while ($more) {  
    $more = $false

    # mark visited urls (note: you can't enumerate a hash table and modify it too)
    foreach($key in @($urls.keys)) {
        # visit all unvisted urls
        if ($urls[$key] -eq $false) {
            $temp = Invoke-WebRequest "$($baseUrl)$($key)" -UseBasicParsing 
            $temp.Content | Out-File $pageMapping[$key]
            $urls[$key] = $true

            # add links from a newly visited url that are unique to a temp hash table
            $temp.Links | 
                Where-Object {$_.href -like "*$($baseDoc)*"} | 
                ForEach-Object {
                    if ((-not $urls.ContainsKey($_.href)) -and (-not $tempUrls.ContainsKey($_.href))) {
                        $tempUrls.Add($_.href, $false)
                        $pageMapping.Add($_.href, 'Toyota'+$count+'.html')
                        $count+=1

                        # loop until no unique urls are found
                        $more = $true
                    }
                }
        }
    }

    # add newly discovered urls to the main hash table
    $tempUrls.GetEnumerator() | 
        ForEach-Object {
            $urls.Add($_.Key, $false)
        }
    $tempUrls.Clear()
}

Write-Output 'STATUS: Downloads complete'
Write-Output 'STATUS: Updating file links'

# update all saved html file links with their new names
$files = Get-ChildItem *.html   # get a listing of all the html files

# iterate through each html file and update any applicable links
foreach($file in $files) {
    $content = (Get-Content $file -Encoding Unicode)

    # scan each line of the file looking for a link to update
    foreach($line in $content) {

        # if the link has a matched link, update it
        # note: [void] is used in front of the string builder variable to suppress its output
        if($line -match $linkRegex) { 
            [void]$tempStr.AppendLine(($line -replace $linkRegex, $pageMapping[$Matches[1]]))
        } else {
            [void]$tempStr.AppendLine($line)
        }
    }
    
    # rewrite the updated content to a file of the same name
    $tempStr.ToString() | Out-File -FilePath $file.Name -Encoding unicode -Force
    # clear the string builder variable so it starts fresh for the next iteration
    [void]$tempStr.Clear()
}
Write-Output 'STATUS: File links updated'
