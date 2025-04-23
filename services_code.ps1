# Get data for all returned services
Get-Service | 
    ForEach-Object { 
        $data = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -Name ImagePath,Description,ServiceDll -ErrorAction SilentlyContinue
        
        if ($data.ImagePath -notlike "*svchost.exe*") {
            
            # remove quotes from quoted file paths and any commandline args
            if ($data.ImagePath -match '^\"') {
                $ImagePath = $data.ImagePath.Split('"')[1]
        
            # remove any commandline args
            } elseif ($data.ImagePath -match "^C:\\Windows\\") {   
                $ImagePath = $data.ImagePath.Split(' ')[0]
        
            # replace \SystemRoot var (e.g. C:\Windows)
            } elseif ($data.ImagePath -match "^\\SystemRoot") {  
                $ImagePath = $data.ImagePath -replace "\\SystemRoot",$env:SystemRoot
        
            # add System Root var (e.g. C:\Windows\) to paths that only start with System32
            } elseif ($data.ImagePath -match "^System32") {  
                $ImagePath = "$($env:SystemRoot)\$($data.ImagePath)"
        
            # remove \??\ if that's the starting path
            } elseif ($data.ImagePath -match "^\\\?\?\\") {   
                $ImagePath = $data.ImagePath -replace "\\\?\?\\",""
            }
            
            $ImageHash = (Get-FileHash $ImagePath).Hash
            $SvcHost = 'False'

        } else {
            
            # add System Root var (e.g. C:\Windows\) to paths that only start with @%System32
            if ($data.Description -match "^@%SystemRoot%") {
                $ImagePath = ($data.Description -replace "@%SystemRoot%",$env:SystemRoot).Split(',')[0]
                
            # add Win Dir path (e.g. C:\Windows\) to paths that only start with @%windir
            } elseif ($data.Description -match "^@%windir%") {
                $ImagePath = ($data.Description -replace "@%windir%",$env:windir).Split(',')[0]
            
            # for a full path dll prefixed with an @ only, remove it
            } elseif ($data.Description -match "^@[a-zA-z]:\\") {
                $ImagePath = ($data.Description -replace "@","").Split(',')[0]
            
            # add the full path to a dll file listing only that starts with @
            } elseif ($data.Description -match "^@[a-zA-z]+\.dll") {
                $ImagePath = ($data.Description -replace "@","$env:SystemRoot\System32\").Split(',')[0]
            
            # output the image path as is    
            } else {
                $ImagePath = $data.Description
            }

            $ImageHash = (Get-FileHash $ImagePath).Hash
            $SvcHost = 'True'
        }

        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Status = $_.Status
            StartType = $_.StartType
            ImagePath = $ImagePath
            ImageHash = $ImageHash
            Svchost = $Svchost
            CanPauseAndContinue = $_.CanPauseAndContinue
            CanShutdown = $_.CanShutdown
            CanStop = $_.CanStop
            ServiceType = $_.ServiceType
        }

    } | Select-Object @{name='Name'; expression={$_.Name}},
                      @{name='DisplayName'; expression={$_.DisplayName}},
                      @{name='Status'; expression={$_.Status}},
                      @{name='StartType'; expression={$_.StartType}},
                      @{name='ImagePath'; expression={$_.ImagePath}},
                      @{name='ImageHash'; expression={$_.ImageHash}},
                      @{name='Svchost'; expression={$_.Svchost}},
                      @{name='CanPauseAndContinue'; expression={$_.CanPauseAndContinue}},
                      @{name='CanShutdown'; expression={$_.CanShutdown}},
                      @{name='CanStop'; expression={$_.CanStop}},
                      @{name='ServiceType'; expression={$_.ServiceType}}
