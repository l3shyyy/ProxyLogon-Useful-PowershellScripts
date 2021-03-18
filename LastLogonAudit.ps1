Get-ADUser -Filter * -Property "LastLogonDate" | Export-CSV "$home\desktop\LastLogonDates.csv" -NoTypeInformation
