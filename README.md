# IdentityDays2019
Les requêtes utilisées lors de la session "Détection de menaces et d'attaques et traitements via Azure Log Analytics, Azure Security Center et Azure Sentinel

SecurityEvent 
|where EventID == 4625


SecurityEvent 
|where EventID == 4625 and Account contains "jef" 
|summarize count() by Account, AccountName, Computer, TimeGenerated
|order by count_ desc 


SecurityEvent 
|where TimeGenerated > ago(14d)
|where EventID == 4625
|summarize count() by tostring(EventID), bin(TimeGenerated, 1d)
| render barchart


SecurityEvent 
|where TimeGenerated > ago(7d)
|where EventID == 4625
|summarize count() by Account | render timechart
|top 10 by count_ desc 



// Merge two request using a function for the first
//Complete the request to identity if there was a brut force attack on these servers
let machinesWithBruteForceAttack = (){ 
Update
|where TimeGenerated >= ago(100d) 
|where UpdateState has "Needed" 
|summarize Computer=makeset(Computer)
};
SecurityDetection
|where TimeGenerated >= ago(100d) 
| where AlertTitle contains "suspicious" 
| where Computer in (machinesWithBruteForceAttack) //in clause to limit us to just these computers
| summarize by Computer


let useradminreset = (){
// Function to obtain the list of User who have made Reset Password
AuditLogs 
| extend UserPrincipalName = InitiatedBy.user.userPrincipalName
| where OperationName == "Reset user password" 
| summarize User=makeset(InitiatedBy.user.userPrincipalName)
};
let DateOperation = (){
AuditLogs 
| where OperationName == "Reset user password" 
| summarize Time=makeset( TimeGenerated)
};
SigninLogs
|where UserPrincipalName in (useradminreset)
|where IPAddress contains "137.117" 
|project UserPrincipalName, IPAddress, TimeGenerated
|summarize IPadress=makeset(IPAddress)