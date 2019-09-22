## Define the username that’s locked out



$Username = read-host "What is the username of the account being locked out?"

$lockedoutCheck = Get-ADUser $UserName -Properties LockedOut 


## Find the domain controller PDCe role
$Pdce = (Get-AdDomain).PDCEmulator

## Build the parameters to pass to Get-WinEvent
$GweParams = @{
     ‘Computername’ = $Pdce
     ‘LogName’ = ‘Security’
     ‘FilterXPath’ = "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$Username']]"
}

## Query the security event log
$Events = Get-WinEvent @GweParams

#Loop through
$LastlockedOutOn= $Events | foreach {$_.Properties[1].Value} 

Write-Host "`n" "Check " -ForegroundColor yellow -NoNewline; Write-Host "$LastlockedOutOn " -ForegroundColor Red -NoNewline; Write-Host " to see if the $Username has any recent lockouts or disconnected sessions?" "`n" -ForegroundColor yellow -NoNewline


$Events | fl






