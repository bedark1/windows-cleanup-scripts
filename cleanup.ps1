function Create-RestorePoint {
    param (
        [string]$description = "System Restore Point"
    )

    # More informative message with description
    Write-Host "Creating a system restore point with description: '$description'..." -ForegroundColor Yellow

    try {
        # Using New-Object with -ComObject parameter for WMI
        $restorePoint = New-Object -ComObject "System.Collections.Generic.Dictionary[[string],[string]]"
        $restorePoint.Add("Description", $description) 

        # Using Get-WmiObject with -Class parameter and -Filter for efficiency
        $systemRestore = Get-WmiObject -Class SystemRestore -Filter "Description='System Restore Point'"
        $result = $systemRestore.CreateRestorePoint($restorePoint, 100) 

        if ($result -eq 0) {
            Write-Host "System restore point created successfully." -ForegroundColor Green
        } else {
            # More specific error message
            Write-Host "Failed to create a system restore point. Error code: $result" -ForegroundColor Red
            # Consider adding error logging here for debugging
        }
    } catch {
        # Handle exceptions, provide user feedback
        Write-Host "An error occurred while creating the restore point: $($_.Exception.Message)" -ForegroundColor Red
        # Consider adding error logging here for debugging
    }
}

# Function to check if running as Administrator (using a built-in method)
function IsAdministrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to restart the script as Administrator
function RestartAsAdmin {
    try {
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile", "-NoExit", "-Command", "& { irm https://raw.githubusercontent.com/bedark1/windows-cleanup-scripts/main/cleanup.ps1 | iex }"
        Write-Host "A new PowerShell window has been opened with administrative privileges."
    } catch {
        Write-Host "Failed to restart with admin privileges: $($_.Exception.Message)" -ForegroundColor Red
        # Consider adding more specific error handling for different error codes
    }
}

# Function to prompt for Administrator privileges
function PromptAdminPrivileges {
    Write-Host "This script requires administrator privileges to run." -ForegroundColor Red
    $choice = Read-Host "Choose an option: [1] Exit [2] Re-run as Administrator " 
    switch ($choice) {
        1 { exit } # No need for Write-Host here before exiting
        2 { RestartAsAdmin }
        default { Write-Host "Invalid choice. Exiting..." -ForegroundColor Red; exit }
    }
}

# Check if running as Administrator
if (-not (IsAdministrator)) {
    PromptAdminPrivileges
    exit  # Exit the current script instance
} 


function Clear-TempFiles {
    $tempPaths = @(
        "$env:windir\Temp", # No need for wildcard here, -Recurse handles it
        "$env:LOCALAPPDATA\Temp"
    )

    Write-Host "TempFiles - Clearing..." -ForegroundColor Yellow # Added "..." for user feedback

    try {
        foreach ($path in $tempPaths) {
            if (Test-Path -Path $path) {  # Check if the path exists
                Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction Stop 
            } else {
                Write-Host "Path not found: $path" -ForegroundColor Yellow # Informative message 
            }
        }
        Write-Host "TempFiles - Done Cleaning" -ForegroundColor Green
    } catch {
        Write-Host "Error during TempFiles cleanup: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Clear-BrowserCache {
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    )

    Write-Host "BrowserData - Clearing..." -ForegroundColor Yellow 

    try {
        foreach ($path in $browserPaths) {
            if (Test-Path -Path $path) { 
                Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction Stop 
            } else {
                Write-Host "Path not found: $path" -ForegroundColor Yellow 
            }
        }
        Write-Host "BrowserData - Done Cleaning" -ForegroundColor Green
    } catch {
        Write-Host "Error during BrowserData cleanup: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Some browser data might be locked. Close the browser and try again." -ForegroundColor Yellow
    }
}

function Clear-RecycleBin {
    Write-Host "RecycleBin - Clearing..." -ForegroundColor Yellow 

    try {
        # Check PowerShell version
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "This script requires PowerShell version 5.0 or higher." -ForegroundColor Red
            return
        }

        # Use the .Empty() method for silent emptying
        [Microsoft.VisualBasic.FileIO.FileSystem].RecycleBin.Empty()

        Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green

    } catch {
        Write-Host "Could not empty the Recycle Bin. Reason: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Fix-WindowsSearchBar {
    Write-Host "Attempting to fix Windows Search Bar issue..." -ForegroundColor Yellow

    try {
        # 1. Restart Windows Search service
        Write-Host "  - Restarting Windows Search service..."
        Restart-Service -Name WSearch -Force -ErrorAction Stop > $null 

        # 2. Re-register relevant DLL files
        Write-Host "  - Re-registering DLL files..."
        $dllFiles = @(
            "C:\Windows\System32\Windows.Storage.Search.dll",
            "C:\Windows\System32\SearchAPI.dll",
            "C:\Windows\System32\msfte.dll"
        )
        foreach ($dll in $dllFiles) {
            if (Test-Path -Path $dll) {
                regsvr32 /s $dll > $null  # Register silently
            }
        }

        # 3. Ensure ctfmon.exe is running (if applicable)
        Write-Host "  - Verifying ctfmon.exe..."
        if (-not (Get-Process ctfmon -ErrorAction SilentlyContinue)) {
            Start-Process -FilePath "ctfmon.exe" > $null # Start silently
        }

        Write-Host "Windows Search Bar fixes applied. Please test the search functionality." -ForegroundColor Green

    } catch {
        Write-Host "An error occurred while trying to fix the Windows Search Bar: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Bufferbloat-SpeedTest {
    # Open the default web browser and navigate to the website
    Start-Process "https://www.waveform.com/tools/bufferbloat"

    # Clear the console for better readability
    Clear-Host 

    # Display a title for the test
    Write-Host "========================"
    Write-Host "  Bufferbloat Test  "
    Write-Host "========================"

    Write-Host "Starting the test in your default web browser..."
    Write-Host "Please click the 'Start Test' button on the website to begin."

    # Display information about bufferbloat grades using a table-like format
    Write-Host ""
    Write-Host "BUFFERBLOAT GRADES"
    Write-Host "------------------"
    Write-Host ("{0,-5} {1}" -f "A:", "Best" ) -ForegroundColor Green
    Write-Host ("{0,-5} {1}" -f "B:", "Good" ) -ForegroundColor Yellow
    Write-Host ("{0,-5} {1}" -f "C:", "Bad"  ) -ForegroundColor Red
    Write-Host ("{0,-5} {1}" -f "D:", "Very Bad") -ForegroundColor Red
    Write-Host ""

    Write-Host "Why is Bufferbloat Important?"
    Write-Host "-----------------------------"
    Write-Host "- Gaming: Bufferbloat can cause lag, affecting performance."
    Write-Host "- General Use: Degrades connectivity during heavy internet usage." 
    Write-Host ""
}


function RunIDM {
    $scriptUrl = "https://massgrave.dev/ias"
    $command = "irm $scriptUrl | iex"

    try {
        Start-Process powershell -ArgumentList "-NoProfile", "-NoExit", "-Command", $command -Verb RunAs
        Write-Host "IDM cleanup script launched in a new window." -ForegroundColor Green
    } catch {
        Write-Host "Failed to launch IDM cleanup script: $($_.Exception.Message)" -ForegroundColor Red
        # Consider adding more specific error handling based on error codes
    }
}

function Install-MB {
    $url = "https://downloads.malwarebytes.com/file/mb-windows"
    $output = "$env:TEMP\mb-windows.exe" # Save to TEMP for easier cleanup

    Write-Host "Downloading Malwarebytes installer..." -ForegroundColor Yellow

    try {
        Invoke-WebRequest -Uri $url -OutFile $output -ErrorAction Stop
        Write-Host "Download completed." -ForegroundColor Green

        if (Test-Path $output) {
            Write-Host "Installing Malwarebytes..." 
            Start-Process -FilePath $output -Wait -PassThru | Out-Null # Install silently
            Write-Host "Malwarebytes installation complete." -ForegroundColor Green
        } else {
            Write-Host "Failed to locate downloaded installer: $output" -ForegroundColor Red
        }

    } catch {
        Write-Host "Failed to download Malwarebytes installer: $($_.Exception.Message)" -ForegroundColor Red
        # Consider adding error logging or more specific error handling
    }
}


function Install-ISLC {
    $7zInstallerUrl = "https://www.7-zip.org/a/7z1900-x64.exe"
    $islcUrl = "https://www.wagnardsoft.com/ISLC/ISLC%20v1.0.3.2.exe"
    $7zInstallerPath = Join-Path $env:TEMP "7zInstaller.exe"
    $islcInstallerPath = Join-Path $env:TEMP "ISLC.exe"

    # Function to download a file with progress display
    function Download-File {
        param (
            [string]$Url,
            [string]$OutputPath
        )
        Write-Host "Downloading: $Url" -ForegroundColor Yellow
        try {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadProgressChanged += { 
                $progress = $_.ProgressPercentage
                Write-Progress -Activity "Downloading" -Status "$progress%" -PercentComplete $progress
            }
            $wc.DownloadFile($Url, $OutputPath)
            Write-Host "Download completed: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error downloading: $($_.Exception.Message)" -ForegroundColor Red
            throw # Re-throw the error to stop the installation process
        }
    }

    # Check if 7-Zip is installed
    if (-not (Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) {
        Write-Host "7-Zip not found. Installing 7-Zip..." 
        try {
            Download-File -Url $7zInstallerUrl -OutputPath $7zInstallerPath
            Start-Process -FilePath $7zInstallerPath -ArgumentList "/S" -Wait -PassThru | Out-Null
            Write-Host "7-Zip installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Failed to install 7-Zip: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "7-Zip is already installed." -ForegroundColor Green
    }

    # Download and install ISLC
    try {
        Download-File -Url $islcUrl -OutputPath $islcInstallerPath
        Start-Process -FilePath $islcInstallerPath -Wait -PassThru | Out-Null
        Write-Host "Intelligent Standby List Cleaner (ISLC) installed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to install ISLC: $($_.Exception.Message)" -ForegroundColor Red
    }
}



function Activate-Windows {
    $scriptUrl = "https://massgrave.dev/get"  # Updated URL

    try {
        # 1. Download the script content
        Write-Host "Downloading Windows activation script..." -ForegroundColor Yellow
        $scriptContent = Invoke-WebRequest -Uri $scriptUrl -ErrorAction Stop
        Write-Host "Script downloaded." -ForegroundColor Green

        # 2. Display the script content to the user 
        Write-Host "The Windows activation script content is:" -ForegroundColor Yellow
        Write-Host $scriptContent.Content -ForegroundColor Cyan
        if ((Read-Host -Prompt "Do you want to review and execute this script? (y/n)") -ne "y") {
            Write-Host "Skipping Windows activation." -ForegroundColor Yellow
            return
        }

        # 3. Execute the script in the CURRENT PowerShell session (elevated)
        Write-Host "Executing Windows activation script..." -ForegroundColor Yellow
        Invoke-Expression $scriptContent.Content 
        Write-Host "Windows activation script executed." -ForegroundColor Green

    } catch {
        # Enhanced error handling
        Write-Host "An error occurred during Windows activation:" -ForegroundColor Red
        if ($_.Exception.Response -ne $null) {
            Write-Host "Status Code: $($_.Exception.Response.StatusCode)" 
            Write-Host "Error Details: $($_.Exception.Response.StatusDescription)"
        } else {
            Write-Host "Error Details: $($_.Exception.Message)"
        }
    }
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


