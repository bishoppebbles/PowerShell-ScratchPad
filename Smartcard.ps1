Get-PnpDevice -Class 'SmartCard' -PresentOnly | Get-PnpDeviceProperty | Where-Object {$_.KeyName -eq 'DEVPKEY_Device_LastArrivalDate'} | Select-Object KeyName,Data