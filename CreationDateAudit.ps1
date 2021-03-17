Get-ADUser -Filter * -Properties "whencreated" | Export-CSV "$env:temp\whencreated.csv"
