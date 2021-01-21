# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1
$expanseV1Server = 'https://expander.expanse.co/api/v1'
$expanseV2Server = 'https://expander.expanse.co/api/v2'
$qadiumV2Server = 'https://expander.qadium.com/api/v2'


# uses the Expander bearer API token to request a short lived JWT token for further Expander inquiries
function Get-JwtToken {
    param ([string]$ApiBearerKey)

    [string]$idTokenRoute=     '/IdToken/'
    [string]$jwtTokenPath=     $expanseV1Server + $idTokenRoute
    $apiBearerKeyHash = @{Authorization="Bearer $ApiBearerKey"}

    $result = Invoke-WebRequest -Uri $jwtTokenPath -Method Get -Headers $apiBearerKeyHash
    
    if($result.StatusCode -eq 200 -and $result.StatusDescription -like "OK") {
        $jwt = ($result | ConvertFrom-Json).token

        # return a JWT token as key/value pair to use for further inquiries
        @{Authorization="JWT $jwt"}
    } else {
        Write-Output "JWT Token request failed. Status Code: $($result.StatusCode) $($result.Description)"
    }       
}

