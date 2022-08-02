Install-Script -Name New-OnPremiseHybridWorker

cd "C:\Program Files\WindowsPowerShell\Scripts"

$NewOnPremiseHybridWorkerParameters = @{
    AutomationAccountName = "AutomationAccountName"
    AAResourceGroupName   = "AAResourceGroupName"
    OMSResourceGroupName  = "OMSResourceGroupName"
    HybridGroupName       = "HybridGroupName"
    SubscriptionID        = "SubscriptionID"
    WorkspaceName         = "WorkspaceName"
  }
  .\New-OnPremiseHybridWorker.ps1 @NewOnPremiseHybridWorkerParameters