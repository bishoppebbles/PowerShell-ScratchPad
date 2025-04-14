Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | 
    ForEach-Object { 
        $data = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.PSChildName)" -Name ImagePath,DisplayName,ServiceDll -ErrorAction SilentlyContinue
        
        if ($data.ImagePath -notlike "*svchost.exe*") {
            
            # remove quotes from quoted file paths and any commandline args
            if ($data.ImagePath -match '^\"') {
                $data.ImagePath = $data.ImagePath.Split('"')[1]
        
            # remove any commandline args
            } elseif ($data.ImagePath -match "^C:\\Windows\\") {   
                $data.ImagePath = $data.ImagePath.Split(' ')[0]
        
            # replace \SystemRoot var (e.g. C:\Windows)
            } elseif ($data.ImagePath -match "^\\SystemRoot") {  
                $data.ImagePath = $data.ImagePath -replace "\\SystemRoot",$env:SystemRoot
        
            # add System Root var (e.g. C:\Windows\) to paths that only start with System32
            } elseif ($data.ImagePath -match "^System32") {  
                $data.ImagePath = "$($env:SystemRoot)\$($data.ImagePath)"
        
            # remove \??\ if that's the starting path
            } elseif ($data.ImagePath -match "^\\\?\?\\") {   
                $data.ImagePath = $data.ImagePath -replace "\\\?\?\\",""
            }
            

        } else {
            
            if ($data.DisplayName -match "^@%SystemRoot%") {
                $data.DisplayName = ($data.DisplayName -replace "@%SystemRoot%",$env:SystemRoot).Split(',')[0]
                $data.DisplayName
            
            } elseif ($data.DisplayName -match "^@%windir%") {
                $data.DisplayName = ($data.DisplayName -replace "@%windir%",$env:windir).Split(',')[0]
                $data.DisplayName
            } elseif ($data.DisplayName -match "^@[a-zA-z]:\\") {
                $data.DisplayName = ($data.DisplayName -replace "@","").Split(',')[0]
                $data.DisplayName
            } elseif ($data.DisplayName -match "^@[a-zA-z]+\.dll") {
                $data.DisplayName = ($data.DisplayName -replace "@","$env:SystemRoot\System32\").Split(',')[0]
                $data.DisplayName
            } else {
                $data.DisplayName
            }
        }

        #$data

    } | Measure-Object # Sort-Object ImagePath -Unique | 
        Select-Object ImagePath,@{Name='ImageHash'; Expression={(Get-FileHash $_.ImagePath).Hash}}


Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | 
    ForEach-Object { 
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.PSChildName)" -Name ImagePath,DisplayName,ServiceDll -ErrorAction SilentlyContinue |
            Where-Object {$_.ImagePath -like "*svchost.exe*"}
} | Select-Object DisplayName | Sort-Object DisplayName | Measure-Object


Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | 
    ForEach-Object { 
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.PSChildName)" -Name ImagePath,DisplayName,ServiceDll -ErrorAction SilentlyContinue |
        Where-Object {$_.ImagePath -notlike "*svchost.exe*"}
} | Select-Object ImagePath | Sort-Object ImagePath


@%SystemRoot%\system32\wpnservice.dll,-1 # replace @%SystemRoot% with $env:SystemRoot and split at ,
@%windir%\system32\bisrv.dll,-100 # replace @%windir% with $env:windir and split at ,
@C:\windows\system32\spool\drivers\x64\3\PrintConfig.dll,-1 # remove the @ and split at ,
@appmgmts.dll,-3250 # Replace the @ and add C:\Windows\System32\ and split at ,
Xbox Accessory Management Service # Don't hash


@appmgmts.dll,-3250
@combase.dll,-5010
@combase.dll,-5012
@comres.dll,-2450
@comres.dll,-2946
@EnterpriseAppMgmtSvc.dll,-1
@gpapi.dll,-112
@WaaSMedicSvc.dll,-100