﻿Get-ADUser -LDAPFilter "(pwdLastSet=0)" | Select SamAccountName,distinguishedName | Export-CSV "C:\Temp\ChangePasswordAtNextLogon.csv"