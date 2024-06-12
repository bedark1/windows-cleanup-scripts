# Function to create a system restore point
function Create-RestorePoint {
    param (
        [string]$description = "System Restore Point"
    )

    Write-Host "Creating a system restore point..." -ForegroundColor Yellow

    $restorePointType = [WMICLASS]"\\.\root\default:SystemRestore"
    $result = $restorePointType.CreateRestorePoint($description, 0, 100)

    if ($result.ReturnValue -eq 0) {
        Write-Host "System restore point created successfully." -ForegroundColor Green
    } else {
        Write-Host "Failed to create a system restore point. Error code: $($result.ReturnValue)" -ForegroundColor Red
    }
}

# Function to check if running as Administrator
function IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to restart the script as Administrator
function RestartAsAdmin {
    $command = "Start-Process PowerShell -ArgumentList '-NoExit', '-Command', 'irm https://raw.githubusercontent.com/bedark1/windows-cleanup-scripts/main/cleanup.ps1 | iex' -Verb RunAs"
    Invoke-Expression $command
}

# Function to prompt for Administrator privileges
function PromptAdminPrivileges {
    Write-Host "You ran the script with no admin privileges." -ForegroundColor Red
    $choice = Read-Host "Choose an option: 1. Exit 2. Re-run with admin privileges"
    switch ($choice) {
        1 { Write-Host "Exiting..."; exit }
        2 {
            Write-Host "Re-running the script with admin privileges..."
            RestartAsAdmin
            Write-Host "A new PowerShell window has been opened with administrative privileges."
            Write-Host "If the new window closed immediately, please check if you have administrative rights."
            exit
        }
        default { Write-Host "Invalid choice. Exiting..."; exit }
    }
}

# Check if running as Administrator
if (-not (IsAdministrator)) {
    PromptAdminPrivileges
}


function Clear-TempFiles {
    $tempPaths = @(
        "$env:windir\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )

    Write-Host "TempFiles - Clearing" -ForegroundColor Yellow
    foreach ($path in $tempPaths) {
        Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
            }
            catch {
                Write-Host "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
            }
        }
    }
    Write-Host "TempFiles - Done Cleaning" -ForegroundColor Green
}

function Clear-BrowserCache {
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*"
    )

    Write-Host "BrowserData - Clearing" -ForegroundColor Yellow
    foreach ($path in $browserPaths) {
        Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
            }
            catch {
                Write-Host "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
            }
        }
    }
    Write-Host "BrowserData - Done Cleaning" -ForegroundColor Green
}

function Fix-WindowsSearchBar {
    Write-Host "Fixing Windows Search Bar issue..." -ForegroundColor Yellow
    try {
        Write-Host "Attempting to run ctfmon.exe with elevated privileges..." -ForegroundColor Cyan
        Start-Process "ctfmon.exe" -Verb RunAs -NoNewWindow
        Write-Host "Windows Search Bar should be fixed. You can now type in it." -ForegroundColor Green
    } catch {
        Write-Host "Failed to fix Windows Search Bar. Error: $_" -ForegroundColor Red
    }
}





function Clear-RecycleBin {
    Write-Host "RecycleBin - Clearing" -ForegroundColor Yellow
    try {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "This script requires PowerShell version 5.0 or higher."
            return
        }

        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)
        $recycleBin.Items() | ForEach-Object {
            $item = $_  # Store the current item in a variable
            try {
                $item.InvokeVerb("delete")
            }
            catch {
                Write-Host "Could not delete item: $($item.Name) - $($_.Exception.Message)"
            }
        }
        [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green
    }
    catch {
        Write-Host "Could not empty the Recycle Bin. Reason: $($_.Exception.Message)"
    }
}


function Bufferbloat-SpeedTest {
    # Open the default web browser and navigate to the website
    Start-Process "https://www.waveform.com/tools/bufferbloat"

    # Prompt the user to start the test
    Write-Host "Please click the 'Start Test' button on the website to begin the test."

    # Display information about bufferbloat grades and their corresponding colors
    Write-Host "`nBUFFERBLOAT GRADE:"
    Write-Host "A: Best" -ForegroundColor Green
    Write-Host "B: Good" -ForegroundColor Yellow
    Write-Host "C: Bad" -ForegroundColor Red
    Write-Host "D: Very Bad" -ForegroundColor Red

    # Display information about the importance of addressing bufferbloat
    Write-Host "It's important to address bufferbloat for both gaming and non-gaming purposes:"
    Write-Host "• For gaming: Bufferbloat can cause noticeable delays (lag), affecting performance and enjoyment."
    Write-Host "• For non-gaming: Bufferbloat can degrade connectivity during heavy internet usage, impacting various activities.`n"
}


function RunIDM {
    $scriptUrl = "https://massgrave.dev/ias"
    $command = "irm $scriptUrl | iex"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -Verb RunAs
    Write-Host "IDM cleanup script executed." -ForegroundColor Green
}

function Install-MB { # Added hyphen 
    $url = "https://downloads.malwarebytes.com/file/mb-windows"
    $output = "mb-windows.exe"

    Write-Host "Downloading Malwarebytes installer..."
    Invoke-WebRequest -Uri $url -OutFile $output

    if (Test-Path $output) {
        Write-Host "Download completed. Installing Malwarebytes..."
        Start-Process -FilePath $output -Wait
        Write-Host "Installation complete."
    } else {
        Write-Host "Failed to download Malwarebytes installer."
    }
}


function Install-ISLC {
    # Check if 7-Zip is installed
    if (-not (Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) {
        # If 7-Zip is not installed, download and install it
        Write-Host "Downloading and installing 7-Zip..."
        $7zInstallerUrl = "https://www.7-zip.org/a/7z1900-x64.exe"
        $7zInstallerPath = Join-Path $env:TEMP "7zInstaller.exe"
        try {
            Invoke-WebRequest -Uri $7zInstallerUrl -OutFile $7zInstallerPath -ErrorAction Stop
            Start-Process -FilePath $7zInstallerPath -ArgumentList "/S" -Wait -PassThru | Wait-Process
            Write-Host "7-Zip installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to download or install 7-Zip: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "7-Zip is already installed." -ForegroundColor Green
    }

    # Download ISLC
    $islcUrl = "https://www.wagnardsoft.com/ISLC/ISLC%20v1.0.3.2.exe"
    $islcInstallerPath = Join-Path $env:TEMP "ISLC.exe"

    Write-Host "Downloading Intelligent Standby List Cleaner (ISLC) installer..."
    try {
        Invoke-WebRequest -Uri $islcUrl -OutFile $islcInstallerPath -ErrorAction Stop
    } catch {
        Write-Host "Failed to download ISLC installer: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Run ISLC installer
    Write-Host "Running ISLC installer..."
    try {
        Start-Process -FilePath $islcInstallerPath -Wait -PassThru
        Write-Host "Intelligent Standby List Cleaner (ISLC) installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install ISLC: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}



function Activate-Windows {
    $scriptUrl = "https://get.activated.win"
    $command = "irm $scriptUrl | iex"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -Verb RunAs
    Write-Host "Windows activation script executed." -ForegroundColor Green
}

function Activate-Office {
    $scriptUrl = "https://get.activated.win"
    $command = "irm $scriptUrl | iex"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -Verb RunAs
    Write-Host "Office activation script executed." -ForegroundColor Green
}
function DirectX-Tweak {
    Write-Host "DirectX Tweak - Applying registry modifications..."
    $registryPath = "HKLM:\SOFTWARE\Microsoft\DirectX"

    $registryValues = @{
        "D3D11_ALLOW_TILING"                        = 1
        "D3D12_CPU_PAGE_TABLE_ENABLED"              = 1
        "D3D12_ALLOW_TILING"                        = 1
        "D3D12_HEAP_SERIALIZATION_ENABLED"          = 1
        "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE"  = 1
        "D3D11_DEFERRED_CONTEXTS"                   = 1
        "D3D12_MAP_HEAP_ALLOCATIONS"                = 1
        "D3D11_ENABLE_DYNAMIC_CODEGEN"              = 1
        "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" = 1
        "D3D12_MULTITHREADED"                       = 1
        "D3D12_RESIDENCY_MANAGEMENT_ENABLED"        = 1
        "D3D11_MULTITHREADED"                       = 1
        "D3D12_RESOURCE_ALIGNMENT"                  = 1
        "D3D12_DEFERRED_CONTEXTS"                   = 1
    }

    foreach ($valueName in $registryValues.Keys) {
        if (-not (Test-Path "$registryPath\")) {
            try {
                New-ItemProperty -Path $registryPath -Name $valueName -Value $registryValues[$valueName] -PropertyType DWORD -Force | Out-Null
                Write-Host "Created registry value: $valueName"
            }
            catch {
                Write-Host "Failed to create registry value: $valueName"
                Write-Host "Error: $_"
            }
        }
        else {
            try {
                Set-ItemProperty -Path $registryPath -Name $valueName -Value $registryValues[$valueName] -ErrorAction Stop
                Write-Host "Modified registry value: $valueName"
            }
            catch {
                Write-Host "Failed to modify registry value: $valueName"
                Write-Host "Error: $_"
            }
        }
    }

    Write-Host "DirectX Tweak - Registry modifications complete."
}



function Disable-PagingFile {
    Create-RestorePoint -description "Before Disabling Paging File"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "c:\pagefile.sys 0 0" -ErrorAction Stop
        Write-Host "Disable-PagingFile  - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Disable-PagingFile - Failed: $_" -ForegroundColor Red
    }
}

function Apply-RegistryTweaks {
    try {
        $regContent = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"ExitLatency"=dword:00000001
"ExitLatencyCheckEnabled"=dword:00000001
"SleepCompatTest"=dword:00000001
"SleepLatencyTest"=dword:00000001
"TestStandby"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"ClearPageFileAtShutdown"=dword:00000001
"LargeSystemCache"=dword:00000001
"SecondLevelDataCache"=dword:00000001
"NonPagedPoolQuota"=dword:00000001
"PagedPoolQuota"=dword:00000001
"PhysicalAddressExtension"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive]
"AdditionalCriticalWorkerThreads"=dword:00000004
"AdditionalDelayedWorkerThreads"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive]
"AdditionalCriticalWorkerThreads"=dword:00000004
"AdditionalDelayedWorkerThreads"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"IdleResiliency"=dword:00000001
"IdleResiliencyCheckEnabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch]
"Start"=dword:00000003

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice]
"Start"=dword:00000004

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc]
"Start"=dword:00000004
"@
        $regFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "registryTweaks.reg")
        $regContent | Out-File -FilePath $regFilePath -Encoding ascii -Force
        Start-Process "regedit.exe" -ArgumentList "/s", $regFilePath -NoNewWindow -Wait
        Write-Host "Apply-RegistryTweaks - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Apply-RegistryTweaks - Failed: $_" -ForegroundColor Red
    }
}
function Disable-UnnecessaryServices {
    try {
        $services = @("SysMain", "WSearch", "DiagTrack", "dmwappushservice", "WMPNetworkSvc")
        foreach ($service in $services) {
            Stop-Service -Name $service -Force -ErrorAction Stop
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Host "$service service disabled successfully."
        }
        Write-Host "Disable-UnnecessaryServices - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Disable-UnnecessaryServices - Failed: $_" -ForegroundColor Red
    }
}

function Adjust-GraphicsAndMultimediaSettings {
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Multimedia\Audio" -Name "DisableProtectedAudioDG" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Direct3D" -Name "ForceDriverVersion" -Value "9.18.13.2049" -ErrorAction Stop
        Write-Host "Adjust-GraphicsAndMultimediaSettings - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Adjust-GraphicsAndMultimediaSettings - Failed: $_" -ForegroundColor Red
    }
}

function Disable-WindowsUpdates {
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction Stop
        Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
        Write-Host "Disable-WindowsUpdates - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Disable-WindowsUpdates - Failed: $_" -ForegroundColor Red
    }
}


function Remove-WindowsBloatware {
    try {
        $bloatwareApps = @(
            "Microsoft.3DBuilder",
            "Microsoft.BingFinance",
            "Microsoft.BingNews",
            "Microsoft.BingSports",
            "Microsoft.BingWeather",
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes",
            "Microsoft.OneConnect",
            "Microsoft.People",
            "Microsoft.Print3D",
            "Microsoft.SkypeApp",
            "Microsoft.Wallet",
            "Microsoft.WindowsFeedbackHub",
            "Microsoft.XboxApp",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"
        )
        foreach ($app in $bloatwareApps) {
            Remove-AppxPackage -Package $app -ErrorAction Stop
            Write-Host "$app removed successfully."
        }
        Write-Host "Remove-WindowsBloatware - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Remove-WindowsBloatware - Failed: $_" -ForegroundColor Red
    }
}


function Disable-UnnecessaryStartupPrograms {
    try {
        $startupItems = @(
            "OneDrive",
            "Skype",
            "Spotify",
            "Cortana"
        )
        foreach ($item in $startupItems) {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $item -Value ""
            Write-Host "$item disabled successfully."
        }
        Write-Host "Disable-UnnecessaryStartupPrograms - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Disable-UnnecessaryStartupPrograms - Failed: $_" -ForegroundColor Red
    }
}


function Revert-AllChanges {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "c:\pagefile.sys" -PassThru -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        foreach ($service in @("SysMain", "WSearch", "DiagTrack", "dmwappushservice", "WMPNetworkSvc")) {
            Start-Service -Name $service -ErrorAction Stop
            Set-Service -Name $service -StartupType Auto -ErrorAction Stop
        }
        Write-Host "Revert-AllChanges - Done" -ForegroundColor Green
    }
    catch {
        Write-Host "Revert-AllChanges - Failed: $_" -ForegroundColor Red
    }
}


function Show-OptimizeMenu {
    Write-Host "1. Optimize Windows Performance (All)"
    Write-Host "2. Disable Paging File"
    Write-Host "3. Apply Registry Tweaks"
    Write-Host "4. Disable Unnecessary Services"
    Write-Host "5. Adjust Graphics and Multimedia Settings"
    Write-Host "6. Disable Windows Updates"
    Write-Host "7. Remove Windows Bloatware"
    Write-Host "8. Disable Unnecessary Startup Programs"
    Write-Host "9. Revert All Changes"
    Write-Host "10. Back to Main Menu"
}


function Optimize-Performance {
    do {
        Show-OptimizeMenu
        $optChoice = Read-Host "Enter your choice"

        switch ($optChoice) {
            1 { 
                # Call each optimization function with feedback for "Optimize All"
                Create-RestorePoint -description "Before Optimize All"
                Disable-PagingFile
                Write-Host "Disable-PagingFile - Done" -ForegroundColor Green
                
                Apply-RegistryTweaks
                Write-Host "Apply-RegistryTweaks - Done" -ForegroundColor Green

                Disable-UnnecessaryServices 
                Write-Host "Disable-UnnecessaryServices - Done" -ForegroundColor Green

                Adjust-GraphicsAndMultimediaSettings
                Write-Host "Adjust-GraphicsAndMultimediaSettings - Done" -ForegroundColor Green

                Disable-WindowsUpdates 
                Write-Host "Disable-WindowsUpdates - Done" -ForegroundColor Green

                Remove-WindowsBloatware
                Write-Host "Remove-WindowsBloatware - Done" -ForegroundColor Green

                Disable-UnnecessaryStartupPrograms
                Write-Host "Disable-UnnecessaryStartupPrograms - Done" -ForegroundColor Green 

                break  # Only one break needed here
            }
            2 { Create-RestorePoint -description "Before Disabling Paging File"; Disable-PagingFile } # No extra feedback for individual options
            3 { Create-RestorePoint -description "Before Applying Registry Tweaks"; Apply-RegistryTweaks }
            4 { Create-RestorePoint -description "Before Disabling Unnecessary Services"; Disable-UnnecessaryServices }
            5 { Create-RestorePoint -description "Before Adjusting Graphics and Multimedia Settings"; Adjust-GraphicsAndMultimediaSettings }
            6 { Create-RestorePoint -description "Before Disabling Windows Updates"; Disable-WindowsUpdates }
            7 { Create-RestorePoint -description "Before Removing Windows Bloatware"; Remove-WindowsBloatware }
            8 { Create-RestorePoint -description "Before Disabling Unnecessary Startup Programs"; Disable-UnnecessaryStartupPrograms }
            9 { Revert-AllChanges }
            10 { Write-Host "Returning to Main Menu..."; break } 
            default { Write-Host "Invalid choice. Please try again." } # Closing quote added!
        }
    } while ($optChoice -ne 10)
}


function Show-MainMenu {
    Write-Host -ForegroundColor Blue -NoNewline "`nWelcome To the All Included Script`nby h4n1 - bdark`n"
    Write-Host -ForegroundColor Yellow -NoNewline "`nEnter your choice:`n"
    Write-Host " Boost:" -ForegroundColor Blue
    Write-Host " 1. Clear Cache"
    Write-Host " 2. Optimize Windows Performance - Carefully! Restore Point will be Made" 
    Write-Host " 3. Intelligent standby list cleaner (ISLC)`n"
    Write-Host " DirectX:" -ForegroundColor Blue
    Write-Host " 4. DirectX Tweak`n"
    Write-Host " Security:" -ForegroundColor Blue
    Write-Host " 5. Install Malwarebytes`n"
    Write-Host " Internet:" -ForegroundColor Blue
    Write-Host " 6. Bufferbloat and Internet Speed Test"
    Write-Host " 7. Install IDM`n"
    Write-Host " Microsoft:" -ForegroundColor Blue
    Write-Host " 8. Install / Activate Windows"
    Write-Host " 9. Install / Activate Office`n"
    Write-Host " 10. Fix Windows Search Bar"
    Write-Host " 11. Exit`n"
}


do {
    Show-MainMenu
    $choice = Read-Host -Prompt "Enter your choice"

    switch ($choice) {
        1 { Clear-TempFiles; Clear-BrowserCache; Clear-RecycleBin }
        2 { Optimize-Performance }
        3 { Install-ISLC }
        4 { DirectX-Tweak }
        5 { Install-MB }
        6 { Bufferbloat-SpeedTest }
        7 { Run-IDM }
        8 { Activate-Windows }
        9 { Activate-Office }
        10 { Create-RestorePoint -description "Before fixing Windows Search Bar"; Fix-WindowsSearchBar }
        11 { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice. Please try again." }
    }
} while ($choice -ne 11)


