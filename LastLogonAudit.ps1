Get-ADUser -Filter * -Property "LastLogonDate" | Export-CSV "$env:temp\LastLogonDates.csv" -NoTypeInformation
