# Author: Sudesh Yalavarthi
# Description: This script is used to detect the presence of a running RMM software on a Windows machine.
# Define the process names to check

$processNames = @(
    "NinjaRMMAgent",
    "AteraAgent",
    "GoToAssist", "GoToMeeting", "GoTo", "GoToSetup",
    "ManageEngine",
    "IntuneManagement",
    "N-central",
    "DesktopCentral",
    "Action1",
    "TeamViewer"
)

# Define the service names to check
$serviceNames = @(
    "NinjaRMMAgent",
    "AteraAgent",
    "GoToAssist", "GoToMeeting", "GoTo",
    "ManageEngine",
    "IntuneManagementExtension",
    "NableAgent",
    "DesktopCentralAgent",
    "Action1Agent",
    "TeamViewer"
)

Write-Host "Checking for RMM tools..."

# Check processes
Write-Host "`nDetected processes:"
foreach ($name in $processNames) {
    $processes = Get-Process | Where-Object ProcessName -like "$name*"
    if ($processes) {
        foreach ($process in $processes) {
            Write-Host "  $($process.ProcessName) (PID: $($process.Id), Path: $($process.Path))"
        }
    }
}

# Check services
Write-Host "`nDetected services:"
foreach ($name in $serviceNames) {
    $services = Get-Service | Where-Object Name -like "$name*"
    if ($services) {
        foreach ($service in $services) {
            $wmiService = Get-WmiObject Win32_Service | Where-Object Name -eq $service.Name
            Write-Host "  $($service.Name) (DisplayName: $($service.DisplayName), Path: $($wmiService.PathName))"
        }
    }
}

