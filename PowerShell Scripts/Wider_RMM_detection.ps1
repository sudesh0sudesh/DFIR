# Author: sudesh Yalavarthi
$fileNames = @(
    'NinjaRMMAgentPatcher.exe',
    'ninjarmm-cli.exe',
    'NinjaRMMAgent.exe',
    'AteraAgent.exe',
    'AgentPackageNetworkDiscoveryWG.exe',
    'AgentPackageAgentInformation.exe',
    'AgentPackageSTRemote.exe',
    'AgentPackageFileExplorer.exe',
    'AgentPackageMonitoring.exe',
    'AgentPackageRuntimeInstaller.exe',
    'GoToAssistService.exe',
    'GoToAssistProcessChecker.exe',
    'G2AC_HostLauncher.exe',
    'G2MInstaller.exe',
    'g2mcomm.exe',
    'g2mlauncher.exe',
    'g2ax_host_service.exe',
    'g2ax_comm_customer.exe',
    'GoToResolveService.exe',
    'GoToAssistTools64.exe',
    'GoToAssistUnattended.exe',
    'GoToSetup-*.exe',
    'GoToAssistCrashHandler.exe',
    'g2mupdate.exe',
    'ClientHealthEval.exe',
    'IntuneManagementExtensionBridge.exe',
    'BridgeLauncher.exe',
    'IntuneWindowsAgent.exe',
    'CopyAgentCatalog.exe',
    'SensorLogonTask.exe',
    'AgentExecutor.exe',
    'SWI_MSP_RC_ViewerUpdate-*.exe',
    'dcagentservice.exe',
    'DCFAService64.exe',
    'dcagentregister.exe',
    'UEMS.exe',
    'dcnginx.exe',
    'EMSAddonInstaller.exe',
    'dcserverhttpd.exe',
    'dcnotificationserver.exe',
    'dcconfig.exe',
    '*-gimp-*-setup.exe',
    'action1_remote.exe',
    'action1_agent.exe',
    'GlassWire.exe'
)

$commonFiles = @(
    'java.exe',
    '7za.exe',
    'postgres.exe',
    'wrapper.exe',
    'wrapper.dll',
    'awt.dll',
    'sunec.dll',
    'freetype.dll',
    'fontmanager.dll',
    'SyMNative.dll',
    'OSDSyMNative.dll'
)

$results = @()

# Search for specific files
foreach ($fileName in $fileNames) {
    $files = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue -Include $fileName -Force
    foreach ($file in $files) {
        $results += [PSCustomObject]@{
            FileName = $file.Name
            FilePath = $file.FullName
            LastWriteTime = $file.LastWriteTime
            FileSize = $file.Length
        }
    }
}

# Search for common files only in specific directories
$specificPaths = @(
    "C:\Program Files*\ManageEngine\*",
    "C:\ManageEngine\*",
    "C:\Program Files*\DesktopCentral*\*"
)

foreach ($fileName in $commonFiles) {
    foreach ($path in $specificPaths) {
        $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Include $fileName -Force
        foreach ($file in $files) {
            $results += [PSCustomObject]@{
                FileName = $file.Name
                FilePath = $file.FullName
                LastWriteTime = $file.LastWriteTime
                FileSize = $file.Length
            }
        }
    }
}

if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize
    Write-Host "Total files found: $($results.Count)"
} else {
    Write-Host "No files found."
}