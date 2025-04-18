# Book: Windows Security Internals (No Starch Press) 
# Author: James Forshaw
# Code snippet to read an arbitrary SID converted to a byte array $ba

$stm = [System.IO.MemoryStream]::new($ba)
$reader = [System.IO.BinaryReader]::new($stm)

revision = $reader.ReadBytes()
if ($revision -ne 1) {
    throw "Invalid SID revision"
}

$rid_count = $reader.ReadByte()
$auth = $reader.ReadBytes(6)
if ($auth.Length -ne 6) {
    throw "Invalid security authority length"
}

$rids = @()
while($rid_count -gt 0) {
    $rids += $reader.ReadUInt32()
    $rid_count--
}


# Book: Windows Security Internals (No Starch Press) 
# Author: James Forshaw
# Code snippet to recursively pull group memberships

function Add-Member($Set, $MemberOf) {
    foreach($name in $MemberOf) {
        if ($Set.Add($name)) {
            $group = Get-ADGroup $name -Properties MemberOf
            Add-Member $Set $group.MemberOf
        }
    }
}

function Get-UserGroupMembership($User) {
    $groups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    Add-Member $groups $User.PrimaryGroup
    Add-Member $groups $User.MemberOf

    $auth_users = Get-ADObject -Filter {
        ObjectClass -eq "foreignSecurityPrincipal" -and Name -eq "S-1-5-11"
    } -Properties memberOf
    Add-Member $groups $auth_users.MemberOf
    $groups | ForEach-Object {Get-DsObjectSid $_}
}
