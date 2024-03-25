$BaseApi = 'https://'
$Ip      = '192.168.1.10'
$Path    = '/hp/device/DeviceStatus/Index'

$Uri = "{0}{1}{2}" -f $BaseApi, $Ip, $Path

$Headers = @{
    'Content-Type'    = 'text/html'
    <#
    'Accept-Encoding' = 'gzip, deflate, br'
    'Accept-Language' = 'en-US,en;q=0.9'
    'Cache-Control'   = 'max-age=0'
    'Connection'      = 'keep-alive'
    #>
}

$Body = @{
    agentIdSelect   = 'hp_EmbeddedPin_v1'
    PinDropDown     = 'AdminItem'
    PasswordTextBox = ''
    signInOk        = 'Sign+In'
}

$RequestProperties = @{
    Uri = $Uri
    Method = 'POST'
    Headers = $Headers
    Body = $Body
}

Invoke-WebRequest @RequestProperties
