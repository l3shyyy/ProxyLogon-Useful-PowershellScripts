Get-ADGroup -Filter * -Property whenChanged, whenCreated | Export-Csv -Path "$home\desktop\AdGroups.csv" -NoTypeInformation
