# two columns of IPv4 & Port

$data = Import-Csv .\printers.csv
$dict = @{}
$final = @{
            '2' = @()
            '3' = @()
         }

foreach($d in $data) {

    if(-not $dict.ContainsKey($d.IPv4)) {
        $dict[$d.IPv4] = @($d.Port)
    } else {
        $dict[$d.IPv4] = $dict[$d.IPv4] += $d.Port
    }
}

foreach($ip in $dict.GetEnumerator()) {

    if($ip.Value.Count -eq 2) {
        $final['2'] = $final['2'] += $ip.Key

    } elseif ($ip.Value.Count -eq 3) {
        $final['3'] = $final['3'] += $ip.Key
    }    
}

Write-Output "2 Printer Ports"
$final['2'] | Sort-Object
Write-Output "Total: $(($final['2'] | Measure-Object).Count)"


Write-Output "`n3 Printer Ports"
$final['3'] | Sort-Object
Write-Output "Total: $(($final['3'] | Measure-Object).Count)"