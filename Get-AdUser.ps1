Get-ADUser -Filter * -Property whenCreated, whenChanged | Export-Csv -Path "$home\desktop\AdUsers.csv" -NoTypeInformation
