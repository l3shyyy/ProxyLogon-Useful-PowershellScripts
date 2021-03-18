Get-ADUser -Filter * -Properties "whencreated" | Export-CSV "$home\desktop\whencreated.csv" -NoTypeInformation
