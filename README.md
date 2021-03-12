# Scheduled-Task-Check
A Simple Powershell script that exports Scheduled Tasks to the Temp Directory. 


To run this command: 

1) Ensure that you can Execution Policy is allowed on your device:<br />
**Set-ExecutionPolicy Unrestricted**<br />
NOTE: After executing, it is good practice to set back to restrcited

2) To generate the log and export to CSV in the C:\Temp\ directory, type:<br />
**.\ScheduledTaskChecker.ps1**
