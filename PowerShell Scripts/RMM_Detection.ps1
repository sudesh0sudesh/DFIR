# Author: Sudesh Yalavarthi
# Description: This script is used to detect the presence of RMM software on a Windows machine.




$fileLocations = @(
    "C:\Program Files*\*\NinjaRMMAgentPatcher.exe",
    "C:\Program Files*\NinjaRMMAgent\NinjaRMMAgentPatcher.exe",
    "C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe",
    "C:\Program Files*\*\NinjaRMMAgent.exe",
    "C:\Program Files*\NinjaRMMAgent\NinjaRMMAgent.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\AteraAgent.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageNetworkDiscoveryWG\AgentPackageNetworkDiscoveryWG.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageAgentInformation\AgentPackageAgentInformation.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageSTRemote\AgentPackageSTRemote.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageFileExplorer\AgentPackageFileExplorer.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageMonitoring\AgentPackageMonitoring.exe",
    "C:\Program Files*\ATERA Networks\AteraAgent\Packages\AgentPackageRuntimeInstaller\AgentPackageRuntimeInstaller.exe",
    "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\GoToAssist Remote Support Applet\*.tmp\GoToAssistService.exe",
    "C:\Users\*\AppData\Local\GoToAssist Remote Support Applet\*.tmp\GoToAssistProcessChecker.exe",
    "C:\Program Files*\LogMeIn\GoToAssist Corporate\*\G2AC_HostLauncher.exe",
    "C:\Program Files*\GoToMeeting\*\G2MInstaller.exe",
    "C:\Users\*\AppData\Local\GoToMeeting\*\g2mcomm.exe",
    "C:\Users\*\AppData\Local\GoToMeeting\*\g2mlauncher.exe",
    "C:\Program Files*\GoToAssist Remote Support Customer\*\g2ax_host_service.exe",
    "C:\Program Files*\GoToAssist Remote Support Customer\*\g2ax_comm_customer.exe",
    "C:\Users\*\AppData\Local\GoTo Resolve Applet\*.tmp\GoToResolveService.exe",
    "C:\Program Files*\GoToAssist Remote Support Unattended\*\GoToAssistTools64.exe",
    "C:\Program Files*\GoToAssist Remote Support Unattended\*\GoToAssistUnattended.exe",
    "C:\Users\*\AppData\Local\goto-updater\pending\GoToSetup-*.exe",
    "C:\Program Files*\GoToMeeting\*\g2mlauncher.exe",
    "C:\Users\*\AppData\Local\GoToAssist Remote Support Applet\*.tmp\GoToAssistCrashHandler.exe",
    "C:\Users\*\AppData\Local\GoToMeeting\*\g2mupdate.exe",
    "C:\ManageEngine\DesktopCentralMSP_Server\jre\bin\java.exe",
    "C:\ManageEngine\ADManager Plus\jre\bin\java.exe",
    "C:\Program Files*\ManageEngine\PMP\tools\archiver\windows\x86-64\7za.exe",
    "C:\ManageEngine\elasticsearch\jre\bin\java.exe",
    "C:\Program Files*\ManageEngine\PMP\jre\bin\java.exe",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\bin\7za.exe",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\bin\wrapper.exe",
    "C:\ManageEngine\OpManager\jre\bin\java.exe",
    "C:\ManageEngine\EventLog Analyzer\jre\bin\java.exe",
    "C:\ManageEngine\ADAudit Plus\pgsql\bin\postgres.exe",
    "C:\ManageEngine\OpManager\Probe\OpManagerProbe\pgsql\bin\postgres.exe",
    "C:\Program Files*\Microsoft Intune Management Extension\ClientHealthEval.exe",
    "C:\Program Files*\WindowsApps\Microsoft.*\IntuneManagementExtensionBridge\IntuneManagementExtensionBridge.exe",
    "C:\Program Files*\WindowsApps\Microsoft.*\BridgeLauncher\BridgeLauncher.exe",
    "C:\Program Files*\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
    "C:\Program Files*\Microsoft Intune Management Extension\Microsoft.Management.Clients.CopyAgentCatalog.exe",
    "C:\Program Files*\Microsoft Intune Management Extension\SensorLogonTask.exe",
    "C:\Program Files*\Microsoft Intune Management Extension\AgentExecutor.exe",
    "C:\Users\*\AppData\Local\MSP Anywhere for N-central\Viewer\Tmp\SWI_MSP_RC_ViewerUpdate-*.exe",
    "C:\Program Files*\DesktopCentral_Agent\bin\dcagentservice.exe",
    "C:\Program Files*\DesktopCentral_Agent\bin\DCFAService64.exe",
    "C:\Program Files*\DesktopCentral_Agent\bin\dcagentregister.exe",
    "C:\Program Files*\DesktopCentral_Server\pgsql\bin\postgres.exe",
    "C:\Program Files*\DesktopCentral_Server\bin\wrapper.exe",
    "C:\ManageEngine\DesktopCentral_Server\bin\wrapper.exe",
    "C:\Program Files*\DesktopCentral_Server\bin\UEMS.exe",
    "C:\Program Files*\DesktopCentral_Server\nginx\dcnginx.exe",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\jre\bin\java.exe",
    "C:\Program Files*\DesktopCentral_Agent\bin\EMSAddonInstaller.exe",
    "C:\ManageEngine\DesktopCentral_Server\jre\bin\java.exe",
    "C:\Program Files*\DesktopCentral_Server\apache\bin\dcserverhttpd.exe",
    "C:\Program Files*\DesktopCentral_Server\bin\7za.exe",
    "C:\Program Files*\DesktopCentral_Server\jre\bin\java.exe",
    "C:\Program Files*\DesktopCentral_Server\bin\dcnotificationserver.exe",
    "C:\Program Files*\DesktopCentral_Agent\dcconfig.exe",
    "C:\Program Files*\DesktopCentral_Agent\patches\*-gimp-*-setup.exe",
    "C:\ManageEngine\AssetExplorer\DesktopCentral_Server\bin\wrapper.exe",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\lib\native\64bit\wrapper.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\jre\bin\awt.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\jre\bin\sunec.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\jre\bin\freetype.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\jre\bin\fontmanager.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\lib\native\64bit\SyMNative.dll",
    "C:\Program Files*\ManageEngine\ServiceDesk\DesktopCentral_Server\lib\native\64bit\OSDSyMNative.dll",
    "C:\Windows\Action1\action1_remote.exe",
    "C:\Windows\Action1\action1_agent.exe",
    "C:\Program Files (x86)\GlassWire\GlassWire.exe",
   
)

$results = @()

foreach ($location in $fileLocations) {
    $files = Get-Item -Path $location -ErrorAction SilentlyContinue
    if ($files) {
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
    Write-Host "Detected files:"
    $results | Format-Table -AutoSize
    Write-Host "Total files found: $($results.Count)"
    
    Write-Host "`nDetected file paths:"
    $results | Select-Object -ExpandProperty FilePath | Sort-Object -Unique
} else {
    Write-Host "No files were detected in the specified locations."
}