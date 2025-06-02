# Populate list of workstations
$computers = @()
$Name = 'site'
$OUdistinguishedName = 'OU=location,DC=domain,DC=com'
$searcher =  [adsiSearcher]"(&(samAccountType=805306369)(msExchExtensionCustomAttribute1=Site|$Name))"
$searcher.SearchRoot = [ADSI]"LDAP://$OUdistinguishedname"
$computers = $searcher.FindAll()

# Job to run
[ScriptBlock]$ScriptBlock =
{
    param (
        [Parameter(Mandatory = $true)] [string]$computer
    )
    #winrm quickconfig [-quiet]  # enable all required PS remoting settings
    #sc.exe \\$computer config winrm start=auto
    #sc.exe \\$computer start winrm
    sc.exe \\$computer query winrm
}

$jobBatchSize = 50
$i = 0
$startTime = Get-Date

foreach($computer in $computers.Properties.name) {
    $i++
    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $computer

    # Run jobs in batches, also ensure the final batch of jobs is run if the total number of jobs is less than $jobBatchSize
    if($i % $jobBatchSize -eq 0 -or $i -eq ($Computers | Measure-Object).Count) {
        Get-Job | Wait-Job -Timeout 90
        # Get-Job | Receive-Job # supresses the job output
        Get-Job | Stop-Job      # must be run first to remove a job if the job if it is still running
        Get-Job | Remove-Job
    }
}

$elapsedTime = ($(Get-Date) - $startTime).ToString("hh\:mm\:ss")
Write-Output "`Processed $(($computers | Measure-Object).Count) workstations in $elapsedTime."
