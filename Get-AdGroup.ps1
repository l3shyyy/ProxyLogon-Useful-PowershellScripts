Get-ADGroup -Filter * -Property whenChanged, whenCreated | Export-Csv -Path "$env:temp\AdGroups.csv" -NoTypeInformation
