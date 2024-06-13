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
            if (Test-Path -Path $path) {
                Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction Stop 
                Write-Host "- Cleared: $path" # Output indicating cleared path
            } else {
                Write-Host "- Path not found: $path" -ForegroundColor Yellow
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
                Write-Host "- Cleared browser cache: $path" # Output for cleared cache
            } else {
                Write-Host "- Path not found: $path" -ForegroundColor Yellow
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
        # ... [Your code to empty the Recycle Bin] ... 

        Write-Host "Recycle Bin - Emptied" -ForegroundColor Green # Confirm Recycle Bin is empty

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
    Write-Host "Windows Activation in Process..."

    # Download the activation script silently
    $scriptContent = Invoke-WebRequest -Uri "https://massgrave.dev/get" -ErrorAction SilentlyContinue
    if (-not $scriptContent) { 
        Write-Host "Failed to download activation script. Check your internet connection." -ForegroundColor Red
        return
    }

    # Execute the script in the background without displaying output
    try {
        Start-Job -ScriptBlock {
            Invoke-Expression $using:scriptContent.Content | Out-Null
        } | Out-Null 

        # (Optional) You can uncomment the following lines to wait for the 
        # background job to complete and check its status:
        # Wait-Job -JobName * # Wait for all jobs (or specify a job name)
        # Get-Job | Receive-Job # Get output from the job (if any) 

        Write-Host "Windows activation script running. Check Other Window." -ForegroundColor Green
    } 
    catch {
        Write-Host "An error occurred while starting the activation process: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Activate-Office {
    Write-Host "Office Activation in Process..."

    # Download the activation script silently
    $scriptContent = Invoke-WebRequest -Uri "https://massgrave.dev/get" -ErrorAction SilentlyContinue
    if (-not $scriptContent) { 
        Write-Host "Failed to download activation script. Check your internet connection." -ForegroundColor Red
        return
    }

    # Execute the script in the background without displaying output
    try {
        Start-Job -ScriptBlock {
            Invoke-Expression $using:scriptContent.Content | Out-Null
        } | Out-Null 

        # (Optional) You can uncomment the following lines to wait for the 
        # background job to complete and check its status:
        # Wait-Job -JobName * # Wait for all jobs (or specify a job name)
        # Get-Job | Receive-Job # Get output from the job (if any) 

        Write-Host "Office activation script running. Check Other Window." -ForegroundColor Green
    } 
    catch {
        Write-Host "An error occurred while starting the activation process: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function DirectX-Tweak {
    # Create a system restore point 
    Create-RestorePoint -description "Before DirectX Tweak" 

    Write-Host "DirectX Tweak - Applying registry modifications (if applicable)..."
    $registryPath = "HKLM:\SOFTWARE\Microsoft\DirectX"

    # Combined registry values
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
        if (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue) { 
            try {
                Set-ItemProperty -Path $registryPath -Name $valueName -Value $registryValues[$valueName] -ErrorAction Stop
                Write-Host "Modified registry value: $valueName"
            }
            catch {
                Write-Host "Failed to modify registry value: $valueName. Error: $_" -ForegroundColor Red
            }
        } 
        else {
            Write-Host "Registry value not found: $valueName (Skipping)"
        }
    }

    Write-Host "DirectX Tweak - Registry modifications complete." 
}



function Disable-PagingFile {
    Create-RestorePoint -description "Before Disabling Paging File"

    Write-Host "Disabling Paging File..." 

    # Get the current paging file configuration
    $memoryManagement = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $pagingFileSetting = Get-ItemPropertyValue -Path $memoryManagement -Name PagingFiles -ErrorAction SilentlyContinue

    # If already disabled, inform the user and exit
    if ($pagingFileSetting -eq "c:\pagefile.sys 0 0" -or $pagingFileSetting -eq "") { 
        Write-Host "Paging File is already disabled or not configured." -ForegroundColor Yellow
        return
    } 

    try {
        # Store the original settings (for potential revert)
        $originalPagingFileSetting = $pagingFileSetting 

        # Disable the paging file
        Set-ItemProperty -Path $memoryManagement -Name PagingFiles -Value "c:\pagefile.sys 0 0" -ErrorAction Stop

        Write-Host "Paging File disabled successfully." -ForegroundColor Green

    } catch {
        Write-Host "Failed to disable Paging File: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Apply-RegistryTweaks {
    Create-RestorePoint -description "Before Applying Registry Tweaks"

    Write-Host "Applying Registry Tweaks..."

    $regContent = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"ExitLatency"=dword:00000001
"ExitLatencyCheckEnabled"=dword:00000001
"SleepCompatTest"=dword:00000001
"SleepLatencyTest"=dword:00000001
"TestStandby"=dword:00000001

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

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"IdleResiliency"=dword:00000001
"IdleResiliencyCheckEnabled"=dword:00000001
"@

    try {
        $regFilePath = Join-Path $env:TEMP "registryTweaks.reg"
        $regContent | Out-File -FilePath $regFilePath -Encoding ascii -Force

        # Use the Registry provider for direct modification
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\DirectX" -ErrorAction SilentlyContinue
        Get-Content $regFilePath | ForEach-Object {
            Invoke-Expression "New-ItemProperty -Path $_.PSPath -Name $_.Property -Value $_.Value -PropertyType $_.PropertyType -Force | Out-Null"
        }

        Write-Host "Registry Tweaks applied successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to apply Registry Tweaks: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Disable-UnnecessaryServices {
    Create-RestorePoint -description "Before Disabling Unnecessary Services"
    
    Write-Host "Disabling Unnecessary Services..."
    $services = @("SysMain", "WSearch", "DiagTrack", "dmwappushservice", "WMPNetworkSvc")

    try {
        foreach ($service in $services) {
            # Combine Stop-Service and Set-Service for efficiency
            Get-Service -Name $service | Stop-Service -Force -ErrorAction SilentlyContinue
            Get-Service -Name $service | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue 

            if ((Get-Service -Name $service).Status -eq "Stopped") {
                Write-Host "$service service disabled successfully." 
            } else {
                Write-Host "Failed to disable $service. It might be needed by another process." -ForegroundColor Yellow
            }
        }

        Write-Host "Unnecessary Services disabled." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred while disabling services: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Adjust-GraphicsAndMultimediaSettings {
    Create-RestorePoint -description "Before Adjusting Graphics & Multimedia"

    Write-Host "Adjusting Graphics and Multimedia Settings..."

    try {
        # Disable Protected Audio (if it exists)
        $audioPath = "HKCU:\Software\Microsoft\Multimedia\Audio"
        if (Get-ItemProperty -Path $audioPath -Name DisableProtectedAudioDG -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $audioPath -Name DisableProtectedAudioDG -Value 1 -ErrorAction Stop
            Write-Host "- Disabled Protected Audio."
        }

        # Set ForceDriverVersion (if the key exists)
        $d3dPath = "HKCU:\Software\Microsoft\Direct3D"
        if (Test-Path -Path $d3dPath) { 
            Set-ItemProperty -Path $d3dPath -Name ForceDriverVersion -Value "9.18.13.2049" -ErrorAction Stop
            Write-Host "- Set ForceDriverVersion to 9.18.13.2049." 
        }

        Write-Host "Graphics and Multimedia settings adjusted." -ForegroundColor Green

    } catch {
        Write-Host "Failed to adjust settings: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Disable-WindowsUpdates {
    Create-RestorePoint -description "Before Disabling Windows Updates"

    Write-Host "Disabling Windows Updates..."
    try {
        # Stop and disable the Windows Update service
        if ((Get-Service -Name wuauserv).Status -eq "Running") { 
            Get-Service -Name wuauserv | Stop-Service -Force -ErrorAction Stop 
        }
        Get-Service -Name wuauserv | Set-Service -StartupType Disabled -ErrorAction Stop

        Write-Host "Windows Update service disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable Windows Updates: $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Remove-WindowsBloatware {
    Create-RestorePoint -description "Before Removing Bloatware"

    Write-Host "Removing Windows Bloatware..."
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

    try {
        foreach ($app in $bloatwareApps) {
            # Check if the app is installed
            if (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue) {
                Remove-AppxPackage -Package $app -ErrorAction Stop 
                Write-Host "- $app removed successfully."
            } else {
                Write-Host "- $app is not installed." 
            }
        }
        Write-Host "Bloatware removal complete." -ForegroundColor Green
    } catch {
        Write-Host "An error occurred during bloatware removal: $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Disable-UnnecessaryStartupPrograms {
    Create-RestorePoint -description "Before Disabling Startup Programs"

    Write-Host "Disabling Unnecessary Startup Programs..."
    $startupItems = @(
        "OneDrive",
        "Skype",
        "Spotify",
        "Cortana"
    )

    try {
        foreach ($item in $startupItems) {
            # Check if the startup item exists
            if (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $item -ErrorAction SilentlyContinue) {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $item -Value "" 
                Write-Host "- $item disabled from startup." 
            } else {
                Write-Host "- $item is not in the startup list."
            }
        }
        Write-Host "Unnecessary Startup Programs disabled." -ForegroundColor Green 
    } catch {
        Write-Host "An error occurred while disabling startup programs: $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Revert-AllChanges {
    Write-Host "Reverting all changes..." -ForegroundColor Yellow
    Write-Host "This will use System Restore and require a system restart."
    if ((Read-Host -Prompt "Are you sure you want to proceed? (y/n)") -eq "y") {
        rstrui.exe /restore /norestart 
        Write-Host "System Restore initiated. Please follow the on-screen prompts."
    } else {
        Write-Host "Revert process cancelled."
    }
}

# ...[Your Optimized Functions]... 

function Show-OptimizeMenu {
    Clear-Host # Clear the console for a cleaner menu
    Write-Host "========================================"
    Write-Host "          Optimize Windows           "
    Write-Host "========================================"
    Write-Host "1.  Optimize All (Recommended)"
    Write-Host "2.  Disable Paging File"
    Write-Host "3.  Apply Registry Tweaks"
    Write-Host "4.  Disable Unnecessary Services"
    Write-Host "5.  Adjust Graphics & Multimedia"
    Write-Host "6.  Disable Windows Updates (Use with caution)" 
    Write-Host "7.  Remove Windows Bloatware"
    Write-Host "8.  Disable Unnecessary Startup Programs"
    Write-Host "9.  Back to Main Menu"
    Write-Host "----------------------------------------"
}

function Optimize-Performance {
    do {
        Show-OptimizeMenu
        $optChoice = Read-Host "Enter your choice"

        switch ($optChoice) {
            1 { 
                Write-Host "Optimizing All: This might take a while..." -ForegroundColor Cyan
                Create-RestorePoint -description "Before Optimize All"
                Disable-PagingFile
                Apply-RegistryTweaks
                Disable-UnnecessaryServices 
                Adjust-GraphicsAndMultimediaSettings
                Disable-WindowsUpdates 
                Remove-WindowsBloatware
                Disable-UnnecessaryStartupPrograms
                Write-Host "All optimizations applied." -ForegroundColor Green
                break 
            }
            2 { Create-RestorePoint -description "Before Disabling Paging File"; Disable-PagingFile }
            3 { Create-RestorePoint -description "Before Applying Registry Tweaks"; Apply-RegistryTweaks }
            4 { Create-RestorePoint -description "Before Disabling Unnecessary Services"; Disable-UnnecessaryServices }
            5 { Create-RestorePoint -description "Before Adjusting Graphics & Multimedia"; Adjust-GraphicsAndMultimediaSettings }
            6 { Create-RestorePoint -description "Before Disabling Windows Updates"; Disable-WindowsUpdates }
            7 { Create-RestorePoint -description "Before Removing Bloatware"; Remove-WindowsBloatware }
            8 { Create-RestorePoint -description "Before Disabling Startup Programs"; Disable-UnnecessaryStartupPrograms }
            9 { break } # Go back to Main Menu
            default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red } 
        } 
    } while ($optChoice -ne 9)
}

function Show-MainMenu {
    Clear-Host # Clear the console for a cleaner menu 
    Write-Host -ForegroundColor Blue -NoNewline "`n  Windows Optimization Script"
    Write-Host -ForegroundColor Blue -NoNewline "  by h4n1 - bdark`n"
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "  Choose an option:" -ForegroundColor Yellow

    Write-Host "----------------------------------------"
    Write-Host "1.  Clear Cache & Temp Files"
    Write-Host "2.  Optimize Windows Performance"
    Write-Host "3.  Intelligent Standby List Cleaner (ISLC)"
    Write-Host "4.  DirectX Tweak"
    Write-Host "5.  Install Malwarebytes"
    Write-Host "6.  Bufferbloat & Internet Speed Test"
    Write-Host "7.  Install IDM"
    Write-Host "8.  Activate Windows"
    Write-Host "9.  Activate Office"
    Write-Host "10. Fix Windows Search Bar"
    Write-Host "11. Revert All Changes (Using System Restore)"
    Write-Host "12. Exit"
    Write-Host "----------------------------------------"
}


do {
    Show-MainMenu
    $choice = Read-Host -Prompt "Enter your choice"

    switch ($choice) {
        1 { 
            Clear-TempFiles 
            Clear-BrowserCache 
            Clear-RecycleBin 
        } # Call each function on a separate line
        2 { Optimize-Performance }
        3 { Install-ISLC }
        4 { DirectX-Tweak }
        5 { Install-MB }
        6 { Bufferbloat-SpeedTest }
        7 { RunIDM } 
        8 { Activate-Windows }
        9 { Activate-Office }
        10 { Create-RestorePoint -description "Before Fixing Windows Search Bar"; Fix-WindowsSearchBar }
        11 { Revert-AllChanges }
        12 { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
    }
} while ($choice -ne 12)

