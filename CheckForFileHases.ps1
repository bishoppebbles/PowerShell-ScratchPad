# check for the existent of specific file hashes

$list = 'system1',
        'system2',
        'system3',
        'system4'

New-PSSession $list

# note: ToUpper() is probably not required but I need to confirm

Invoke-Command -Session (Get-PSSession) -ScriptBlock {
    Get-ChildItem -Recurse 'C:\Program Files (x86)\SolarWinds\','C:\WINDOWS\SysWOW64\*.dll' |
    ForEach-Object {Get-FileHash $_.FullName -Algorithm SHA256} |
    Where-Object {
	$_.Hash -like ("32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77").ToUpper() -or
	$_.Hash -like ("dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b").ToUpper() -or
        $_.Hash -like ("eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed").ToUpper() -or
        $_.Hash -like ("c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77").ToUpper() -or
	$_.Hash -like ("ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c").ToUpper() -or
	$_.Hash -like ("019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134").ToUpper() -or
	$_.Hash -like ("ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6").ToUpper() -or
	$_.Hash -like ("a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc").ToUpper() -or
	$_.Hash -like ("d3c6785e18fba3749fb785bc313cf8346182f532c59172b69adfb31b96a5d0af").ToUpper() -or
        $_.Hash -like ("d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600").ToUpper() -or
        $_.Hash -like ("c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71").ToUpper()
    }
}

Remove-PSSession *