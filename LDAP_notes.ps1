#Without Get-ADComputer cmdlet (ActiveDirectory RSAT module):
# The sAMAccountType is an LDAP attribute used to classify different types of security principals within Active Directory. 
# sAMAccountType 805306369 identifies a computer account (user accounts have a sAMAccountType 805306368) 

$ComputerDomainDNSname = "domain.com"
$ComputerOUdistinguishedname = "OU=Servers,OU=Location,DC=domain,DC=com"

$computers = [adsisearcher]::new([adsi]"LDAP://$ComputerDomainDNSname/$ComputerOUdistinguishedname","(&(samAccountType=805306369))").FindAll()

foreach ($computer in $computers) 
{
        $name = $computer.properties.name
        $cn = $computer.properties.cn 
        $samname = $computer.Properties.samaccountname
        $spn = $computer.Properties.serviceprincipalname
        $dn = $computer.Properties.distinguishedname
        $pwddate = [datetime]::fromfiletime($computer.properties.pwdlastset[0])
        $logonts = [datetime]::fromfiletime($computer.properties.lastlogon[0]) 
        $lastlogonts = [datetime]::fromfiletime($computer.properties.lastlogontimestamp[0])
        $mea01 = $computer.properties.extensionattribute1
        $mea02 = $computer.properties.extensionattribute2
        $mea03 = $computer.properties.extensionattribute3
        $mea04 = $computer.properties.extensionattribute4
        $mea05 = $computer.properties.extensionattribute5
        $mea06 = $computer.properties.extensionattribute6
        $mea07 = $computer.properties.extensionattribute7
        $mea08 = $computer.properties.extensionattribute8
        $mea09 = $computer.properties.extensionattribute9
        $mea10 = $computer.properties.extensionattribute10
        $mea11 = $computer.properties.extensionattribute11
        $mea12 = $computer.properties.extensionattribute12
        $mea13 = $computer.properties.extensionattribute13
        $mea14 = $computer.properties.extensionattribute14
        $mea15 = $computer.properties.extensionattribute15
        $meea18 = $computer.properties.msexchextensionattribute18
        $meca1 = $computer.properties.msexchextensioncustomattribute1
        $meca2 = $computer.properties.msexchextensioncustomattribute2
        $meca3 = $computer.properties.msexchextensioncustomattribute3
        $meca4 = $computer.properties.msexchextensioncustomattribute4
        $meca5 = $computer.properties.msexchextensioncustomattribute5
        $manager = $computer.properties.manager
         

        Write-Host "name: " $name "`nContainer Name: " $cn "`nSamAccountName: " $samname "`nServicePrincpalName: " $spn "`ndistinguishedname: " $dn  "`nPassword Last Set: " $pwddate "`nLastlogon: " $logonts "`nLastlogonTimestamp: " $lastlogonts "`nManager DN: " $manager "`nExtensionAttribute1: " $mea01 "`nExtensionAttribute2: " $mea02 "`nExtensionAttribute3: " $mea03 "`nExtensionAttribute4: " $mea04 "`nExtensionAttribute5: " $mea05 "`nExtensionAttribute6: " $mea06 "`nExtensionAttribute7: " $mea07 "`nExtensionAttribute8: " $mea08 "`nExtensionAttribute9: " $mea09 "`nExtensionAttribute10: " $mea10 "`nExtensionAttribute11: " $mea11 "`nExtensionAttribute12: " $mea12 "`nExtensionAttribute13: " $mea13 "`nExtensionAttribute14: " $mea14 "`nExtensionAttribute15: " $mea15 "`nmsExchExtensionAttribute18: " $meea18 "`nMSExchangeCustomAttribute1: " $meca1 "`nMSExchangeCustomAttribute2: " $meca2 "`nMSExchangeCustomAttribute3: " $meca3 "`nMSExchangeCustomAttribute4: " $meca4 "`nMSExchangeCustomAttribute5: " $meca5 "`n`n`n`n"
}




# A slightly different approach
# Group ID of 515 is the Domain Computers group (all domain joined computers except domain controllers)
$sourceName = 'OU=Workstations,OU=Location,DC=domain,DC=com'
$Name = 'location'
$searcher =  [adsiSearcher]"(&(primaryGroupId=515)(msExchExtensionCustomAttribute1=iPostSite|$Name))"
$searcher.SearchRoot = [ADSI]"LDAP://$(${env:LOGONSERVER}.Trim('\'))/$sourceName"
$searcher.SearchScope =  [System.DirectoryServices.SearchScope]::OneLevel 
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.Add('name') | Out-Null
$searcher.Sort.PropertyName = 'name'
$computers = $searcher.FindAll().Properties.name #[0]