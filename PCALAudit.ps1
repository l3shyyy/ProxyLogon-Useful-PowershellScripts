Get-ADUser -LDAPFilter "(pwdLastSet=0)" | Select SamAccountName,distinguishedName | Export-CSV "$home\desktop\ChangePasswordAtNextLogon.csv" -notypeinformation
