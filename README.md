# Introduction
Hello! In light of the recent ProxyLogon attacks - I am keeping track of useful powershell scripts that may benefit system administrators. These scripts may vary and may not be useful to everyone, but may benefit outlier organizations. I will do my best to continue to update these scripts as time goes on. 

Thank you for reading! 

Ensure Execution Policy is allowed on your device:<br />
**Set-ExecutionPolicy Unrestricted**<br />
NOTE: After executing, it is good practice to set back to restrcited

# Scheduled-Task-Check
**Description:** A Simple Powershell script that exports Scheduled Tasks to the Desktop. Can help in locating tasks scheduled by attackers for persistence on system.

**Usage:** <br />
**.\ScheduledTaskChecker.ps1**

Results will be found on your desktop.

# PCAL Audit (Password Change at Logon Audit)
**Description:** A simple script you can run to verify what users are set to change their password at next logon. 

**Usage:**<br /> 
.\PCALAudit.ps1

Results will be found on your desktop.

# Last Logon Audit
**Description:** A simple Powershell script to show when the last time a user signed in was along with additional information about that user object. 

**Usage:**<br /> 
.\LastLogonAudit.ps1

Results will be found on your desktop.

# Creation Date Audit
**Description:** A simple Powershell script to show when a user account was created along with additional information about the user object. 

**Usage:**<br />
.\CreationDateAudit.ps1

Results will be found on your desktop.

------------------------------------------------------------------------------------------------------------------------------------
Please check out https://github.com/adamrpostjr/cve-2021-27065 for the following scripts to collect newly created AD Users / AD Groups

# Get AD Groups and when they were created (Get-AdGroup.ps1)
**Description:** A simple script to collect AD Groups and when they were created. 

**Usage:** <br />
.\Get-AdGroup.ps1

Results will be found on your desktop.


# Get AD Users and when they were created (Get-AdUser.ps1)
**Description:**A simple script to collect AD Users and when they were created. 

**Usage:** <br />
.\Get-AdUser.ps1

Results will be found on your desktop.

------------------------------------------------------------------------------------------------------------------------------------
From Official MS GitHub found at https://github.com/microsoft/CSS-Exchange/tree/main/Security. Only including files for convenience. 
Please see usage on there GitHub 
- Test-ProxyLogon.ps1
- ExchangeMitigations.ps1
- http-vuln-cve2021-26855.nse
- EOMT.ps1

# http-vuln-cve2021-26855.nse
I have not seen usage clearly described on the official MS GitHub. It is as follows assuming http-vuln-cve2021-26855.nse is in the same directory you are scanning from: <br /> 

nmap -p 443 --script=http-vuln-cve2021-26855.nse exchange.domain.com<br /> 
or <br /> 
nmap -p 443 --script=http-vuln-cve2021-26855.nse [Exchange WAN IP]  

 
