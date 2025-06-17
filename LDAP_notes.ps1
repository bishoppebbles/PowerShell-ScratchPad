# Populate list of workstations
$computers = @()
$Name = 'wuhan'
$Domain = 'state.sbu'
$OUdistinguishedName = 'OU=State Dept,DC=state,DC=sbu'
$searcher =  [adsiSearcher]"(&(samAccountType=805306369)(msExchExtensionCustomAttribute1=iPostSite|$Name))"
$searcher.SearchRoot = [ADSI]"LDAP://$Domain/$OUdistinguishedname"
$computers = $searcher.FindAll()

[ScriptBlock]$Enable_PSRemoting = {
    param (
    	[Parameter(Mandatory = $true)] [string]$computer
    )

    $cimSessOption = New-CimSessionOption -Protocol Dcom

    if(Test-Connection $computer -Count 1) {          
        $cimSession = New-CimSession -ComputerName $computer -SessionOption $cimSessOption
        Invoke-CimMethod -ClassName 'Win32_Process' `
                         -MethodName 'Create' `
                         -CimSession $cimSession `
                         -Arguments @{CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"} | Out-Null
        $cimSession | Remove-CimSession

        if(Test-WSMan -ComputerName $computer) {
            Write-Output "PS Remoting was enabled on $computer"
        } else {
            Write-Output "PS Remoting was not enabled on $computer"
        }
    } else {
        Write-Output "$computer is not reachable"
    }
}

[ScriptBlock]$Enable_WinRM = {
    param (
        [Parameter(Mandatory = $true)] [string]$computer
    )

    sc.exe \\$computer config winrm start=auto
    sc.exe \\$computer start winrm
    #sc.exe \\$computer query winrm
}

$jobBatchSize = 50
$i = 0
$startTime = Get-Date

foreach($computer in $computers) {
    $i++
    Start-Job -ScriptBlock $Enable_PSRemoting -ArgumentList $computer
    #Start-Job -ScriptBlock $Enable_WinRM -ArgumentList $computer

    # Run jobs in batches, also ensure the final batch of jobs is run if the total number of jobs is less than $jobBatchSize
    if($i % $jobBatchSize -eq 0 -or $i -eq ($Computers | Measure-Object).Count) {
        Get-Job | Wait-Job -Timeout 90
        Get-Job | Receive-Job   # supresses the job output
        Get-Job | Stop-Job      # must be run first to remove a job if the job if it is still running
        Get-Job | Remove-Job
    }
}

$elapsedTime = ($(Get-Date) - $startTime).ToString("hh\:mm\:ss")
Write-Output "`Processed $(($computers | Measure-Object).Count) workstations in $elapsedTime."
