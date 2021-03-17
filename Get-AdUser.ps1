Get-ADUser -Filter * -Property whenCreated, whenChanged | Export-Csv -Path "$env:temp\AdUsers.csv" -NoTypeInformation
