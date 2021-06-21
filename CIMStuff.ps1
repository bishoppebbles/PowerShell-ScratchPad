# View the Class definitions in a Namespace
Get-CimClass
Get-CimClass –ClassName <name> | Select-Object –ExpandProperties <properties>


# Check the local accounts on remote computer
Get-CimInstance -ClassName Win32_UserAccount -ComputerName <computerName> -Filter "LocalAccount='True'" | Format-Table Caption,Disabled –AutoSize
Get-WmiObject -ClassName Win32_UserAccount -ComputerName <computerName> -Filter "LocalAccount='True'" | Format-Table Caption,Disabled -AutoSize

# Remove a local user profile named "user_name"
Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.LocalPath('\')[-1] -eq 'user_name'} | Remove-CimInstance
