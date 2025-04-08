# Script that decodes Cisco's type 7 weak "encryption" and displays the plaintext password
# Adapted from theevilbit@github's python script (MIT license)
# By John Savu April 2024
 
function Decrypt-Type7 {
    param(
        [string]$type7
    )
 
    if (($type7.Length % 2) -ne 0) {
        Write-Output 'Valid type 7 password length must be even'
        return
    }
 
    $password = ''
    $xlat = @(0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
              0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
              0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73,
              0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 
              0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 
              0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37)
    
    $type7 -match '(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)' | Out-Null
        
    $s = [int]$Matches[1]
    $e = $Matches[2]
    
    for ($pos = 0; $pos -lt $e.Length; $pos += 2) {
        $magic = [convert]::ToInt32($e.Substring($pos, 2), 16)
        
        if ($s -le 50) {
            $newchar = [char]($magic -bxor $xlat[$s])
            $s++
        }
        
        if ($s -eq 51) { $s = 0 }
        $password += $newchar
    }
    
    [pscustomobject]@{
        Type7   = $type7
        Password= $password
    }
}
 
# Decrypt-Type7 <type7_password>
