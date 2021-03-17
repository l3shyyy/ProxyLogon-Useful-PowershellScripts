Get-ADUser -LDAPFilter "(pwdLastSet=0)" | Select SamAccountName,distinguishedName | Export-CSV "$env:temp\ChangePasswordAtNextLogon.csv" -notypeinformation
