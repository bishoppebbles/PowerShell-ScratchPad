$comClassId = Get-ChildItem HKLM:\SOFTWARE\Classes\CLSID

#$out = foreach($class in $comClassId) {

foreach($class in $comClassId[0..1000]) {
    
    $server = Get-ItemProperty -Path ($class.PSPath -replace "Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:")
    $library = Get-ChildItem ($server.PSPath -replace "Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:")
    
    foreach($lib in $library) {
        Get-ItemProperty -Path ($lib.PSPath -replace "Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE","HKLM:") |
            Where-Object {$_.'(default)' -like "*.dll*" -or $_.'(default)' -like "*.exe*"} |
            Select-Object @{name='Class'; expression={$class.PSChildName}},@{name='Server'; expression={$server.'(default)'}},PSChildName,'(default)'
    }
}

#$out | Export-Csv com.csv -NoTypeInformation
