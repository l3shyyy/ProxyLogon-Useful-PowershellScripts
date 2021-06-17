Get-ADUser -Filter * -Property whenCreated, whenChanged | Export-Csv -Path "$home\desktop\AdUsers.csv" -NoTypeInformation
#or to the temp directory: 
Get-ADUser -Filter * -Property whenCreated, whenChanged | Export-Csv -Path "C:\Temp\Updated-Users.csv" -NoTypeInformation
