# Introduction
Hello! In light of the recent ProxyLogon attacks - I am keeping track of useful powershell scripts that may benefit system administrators. These scripts may vary and may not be useful to everyone, but may benefit outlier organizations. I will do my best to continue to update these scripts as time goes on. 

Thank you for reading! 

Ensure Execution Policy is allowed on your device:<br />
**Set-ExecutionPolicy Unrestricted**<br />
NOTE: After executing, it is good practice to set back to restrcited

# Scheduled-Task-Check
**Description:** A Simple Powershell script that exports Scheduled Tasks to the Temp Directory. Can help in locating tasks scheduled by attackers for persistence on system.

**Usage:** <br />
**.\ScheduledTaskChecker.ps1**

Results will be found at C:\temp\[DATE]ScheduledTasks.csv

# PCAL Audit (Password Change at Logon Audit)
**Description:** A simple script you can run to verify what users are set to change their password at next logon. 

**Usage:**<br /> 
.\PCALAudit.ps1

Results will be found at C:\Temp\ChangePasswordAtNextLogon.csv

# Last Logon Audit
**Description:** A simple Powershell script to show when the last time a user signed in was along with additional information about that user object. 

**Usage:**<br /> 
.\LastLogonAudit.ps1

Results will be found at C:\Temp\LastLogonDates.csv


------------------------------------------------------------------------------------------------------------------------------------
From Official MS GitHub found at https://github.com/microsoft/CSS-Exchange/tree/main/Security. Only including files for convenience. 
Please see usage on there GitHub 
- Test-ProxyLogon.ps1
- ExchangeMitigations.ps1
- http-vuln-cve2021-26855.nse

# http-vuln-cve2021-26855.nse
I have not seen usage clearly described on the official MS GitHub. It is as follows assuming http-vuln-cve2021-26855.nse is in the same directory you are scanning from: <br /> 

nmap -p 443 --script=http-vuln-cve2021-26855.nse exchange.domain.com<br /> 
or <br /> 
nmap -p 443 --script=http-vuln-cve2021-26855.nse [Exchange WAN IP]  

 
