function Is-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-AsAdmin {
    $command = "Start-Process PowerShell -ArgumentList '-NoExit', '-Command', 'irm https://raw.githubusercontent.com/bedark1/windows-cleanup-scripts/main/cleanup.ps1 | iex' -Verb RunAs"
    Invoke-Expression $command
}

function Prompt-AdminPrivileges {
    Write-Host "You ran the script with no admin privileges." -ForegroundColor Red
    $choice = Read-Host "Choose an option: 1. Exit 2. Re-run with admin privileges"
    switch ($choice) {
        1 { Write-Host "Exiting..."; exit }
        2 {
            Write-Host "Re-running the script with admin privileges..."
            Restart-AsAdmin
            Write-Host "A new PowerShell window has been opened with administrative privileges."
            Write-Host "If the new window closed immediately, please check if you have administrative rights."
            exit
        }
        default { Write-Host "Invalid choice. Exiting..."; exit }
    }
}

if (-not (Is-Administrator)) {
    Prompt-AdminPrivileges
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
            } catch {
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
            } catch {
                Write-Host "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
            }
        }
    }
    Write-Host "BrowserData - Done Cleaning" -ForegroundColor Green
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
            try {
                $_.InvokeVerb("delete")
            } catch {
                Write-Host "Could not delete item: $($_.Name) - $($_.Exception.Message)"
            }
        }
        [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green
    } catch {
        Write-Host "Could not empty the Recycle Bin. Reason: $_.Exception.Message"
    }
}

function Run-IDM {
    $scriptUrl = "https://massgrave.dev/ias"
    $command = "irm $scriptUrl | iex"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -Verb RunAs
    Write-Host "IDM cleanup script executed." -ForegroundColor Green
}

function Install-MB {
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
    $url = "https://www.wagnardsoft.com/ISLC/ISLC%20v1.0.3.2.exe"
    $output = "ISLC.exe"

    Write-Host "Downloading Intelligent Standby List Cleaner (ISLC) installer..."
    Invoke-WebRequest -Uri $url -OutFile $output

    if (Test-Path $output) {
        Write-Host "Download completed. Running ISLC..."
        Start-Process -FilePath $output -Wait
        Write-Host "ISLC execution complete."
    } else {
        Write-Host "Failed to download ISLC installer."
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
        "D3D11_ALLOW_TILING" = 1
        "D3D12_CPU_PAGE_TABLE_ENABLED" = 1
        "D3D12_ALLOW_TILING" = 1
        "D3D12_HEAP_SERIALIZATION_ENABLED" = 1
        "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" = 1
        "D3D11_DEFERRED_CONTEXTS" = 1
        "D3D12_MAP_HEAP_ALLOCATIONS" = 1
        "D3D11_ENABLE_DYNAMIC_CODEGEN" = 1
        "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" = 1
        "D3D12_MULTITHREADED" = 1
        "D3D12_RESIDENCY_MANAGEMENT_ENABLED" = 1
        "D3D11_MULTITHREADED" = 1
        "D3D12_RESOURCE_ALIGNMENT" = 1
        "D3D12_DEFERRED_CONTEXTS" = 1
    }

    foreach ($valueName in $registryValues.Keys) {
        if (-not (Test-Path "$registryPath\$valueName")) {
            try {
                New-ItemProperty -Path $registryPath -Name $valueName -Value $registryValues[$valueName] -PropertyType DWORD -Force | Out-Null
                Write-Host "Created registry value: $valueName"
            } catch {
                Write-Host "Failed to create registry value: $valueName"
                Write-Host "Error: $_"
            }
        } else {
            try {
                Set-ItemProperty -Path $registryPath -Name $valueName -Value $registryValues[$valueName] -ErrorAction Stop
                Write-Host "Modified registry value: $valueName"
            } catch {
                Write-Host "Failed to modify registry value: $valueName"
                Write-Host "Error: $_"
            }
        }
    }

    Write-Host "DirectX Tweak - Registry modifications complete."
}

function Show-MainMenu {
    Write-Host -ForegroundColor Blue -NoNewline "`nWelcome To the All Included Script`nby h4n1 - bdark`n"
    Write-Host -ForegroundColor Yellow -NoNewline "`nEnter your choice:`n"
    Write-Host " Boost:" -ForegroundColor Blue
    Write-Host " 1. Clear Cache"
    Write-Host " 2. Intelligent standby list cleaner (ISLC)`n"
    Write-Host " DirectX:" -ForegroundColor Blue
    Write-Host " 3. DirectX Tweak`n"
    Write-Host " Security:" -ForegroundColor Blue
    Write-Host " 4. Install Malwarebytes`n"
    Write-Host " Internet:" -ForegroundColor Blue
    Write-Host " 5. Install IDM`n"
    Write-Host " Microsoft:" -ForegroundColor Blue
    Write-Host " 6. Install / Activate Windows"
    Write-Host " 7. Install / Activate Office`n"
    Write-Host " 8. Optimize Windows Performance`n"
    Write-Host " 9. Exit`n"
}

function Show-OptimizeMenu {
    Write-Host "Optimize Windows Performance - Choose an option:" -ForegroundColor Cyan
    Write-Host " 1. Disable Paging File: Disables the paging file to minimize hard pagefaults."
    Write-Host " 2. Apply Registry Tweaks: Applies registry tweaks to reduce DPC/ISR latencies."
    Write-Host " 3. Disable Unnecessary Services: Disables certain unnecessary services to reduce background task load."
    Write-Host " 4. Adjust Graphics and Multimedia Settings: Adjusts registry settings for graphics and multimedia performance."
    Write-Host " 5. Disable Windows Updates: Stops and disables the Windows Update service."
    Write-Host " 6. Remove Windows Bloatware: Removes built-in Windows apps that are not necessary."
    Write-Host " 7. Disable Unnecessary Startup Programs: Disables unnecessary startup programs to reduce system load."
    Write-Host " 8. Revert all changes"
}

function Optimize-Performance {
    do {
        Show-OptimizeMenu
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            1 { Disable-PagingFile }
            2 { Apply-RegistryTweaks }
            3 { Disable-UnnecessaryServices }
            4 { Adjust-GraphicsAndMultimediaSettings }
            5 { Disable-WindowsUpdates }
            6 { Remove-WindowsBloatware }
            7 { Disable-UnnecessaryStartupPrograms }
            8 { Revert-AllChanges }
            default { Write-Host "Invalid choice. Please try again." }
        }
    } while ($choice -ne 8)
}

function Clear-TempFiles {
    # The existing implementation for clearing temporary files
}

function Clear-BrowserCache {
    # The existing implementation for clearing browser cache
}

function Clear-RecycleBin {
    # The existing implementation for clearing recycle bin
}

function Run-IDM {
    # The existing implementation for running IDM cleanup script
}

function Install-MB {
    # The existing implementation for installing Malwarebytes
}

function Install-ISLC {
    # The existing implementation for installing ISLC
}

function Activate-Windows {
    # The existing implementation for activating Windows
}

function Activate-Office {
    # The existing implementation for activating Office
}

function Disable-PagingFile {
    # Function to disable the paging file
}

function Apply-RegistryTweaks {
    # Function to apply registry tweaks
}

function Disable-UnnecessaryServices {
    # Function to disable unnecessary services
}

function Adjust-GraphicsAndMultimediaSettings {
    # Function to adjust graphics and multimedia settings
}

function Disable-WindowsUpdates {
    # Function to disable Windows updates
}

function Remove-WindowsBloatware {
    # Function to remove Windows bloatware
}

function Disable-UnnecessaryStartupPrograms {
    # Function to disable unnecessary startup programs
}

function Revert-AllChanges {
    # Function to revert all changes made by optimization functions
}

# Main menu loop
do {
    Show-MainMenu
    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        1 { Clear-TempFiles; Clear-BrowserCache; Clear-RecycleBin }
        2 { Install-ISLC }
        3 { DirectX-Tweak }
        4 { Install-MB }
        5 { Run-IDM }
        6 { Activate-Windows }
        7 { Activate-Office }
        8 { Optimize-Performance }
        9 { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice. Please try again." }
    }
} while ($choice -ne 9)
