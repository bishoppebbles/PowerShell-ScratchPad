# Exchange Online service
Connect-EXOPSSession -UserPrincipalName <user@domain.com>

# Exchange Online Protection and Security & Compliance Center services
Connect-IPPSSession -UserPrincipalName <user@domain.com>

New-MailboxSearch -Name search_name_XX `
                  -SourceMailboxes "<mailbox(es)_of_interest>" `
                  -TargetMailbox "<results_mailbox>" `              
                  -Recipients "<email_recipients>" ` # wildcard "*@domain.com"
                  -StartDate "mm/dd/yyyy" `
                  -EndDate "mm/dd/yyyy" `
                  -SearchQuery 'subject:(Caixin OR "xyz digital*") AND hasattachments:true' | 
    Start-MailboxSearch 

## OR ##

New-MailboxSearch -Name search_name_XX `
                  -SourceMailboxes "<mailbox(es)_of_interest>" `
                  -TargetMailbox "<results_mailbox>" `              
                  -Recipients "<email_recipients>" `  # wildcard "*@domain.com"
                  -SearchQuery 'sent>=04/01/2020 sent<=05/01/2020 subject:pictures' |
    Start-MailboxSearch 

Remove-MailboxSearch -Name search_name_XX -Confirm:$false

Get-MailboxSearch | 
    Where-Object {$_.Name -like "search_name_*"} | 
    Remove-MailboxSearch -Confirm:$false

Get-MailboxSearch | 
    Where-Object {$_.Name -like "search_name_*" -and $_.Status -like "Failed"} | 
    Start-MailboxSearch -Confirm:$false