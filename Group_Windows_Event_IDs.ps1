Get-WinEvent -Path <path.evtx> | 
    Select-Object Id,TaskDisplayName | 
    Group-Object Id | 
    Sort-Object Count -Descending | 
    Select-Object Count,Name,@{name='Description'; expression={$_.Group[0].TaskDisplayName}} | 
    Export-Csv win_events.csv -NoTypeInformation