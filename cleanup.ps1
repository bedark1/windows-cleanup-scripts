# Define a global log file path
$global:logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")

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
                Add-Content -Path $global:logFile -Value "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
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
                Add-Content -Path $global:logFile -Value "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
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
                Add-Content -Path $global:logFile -Value "Could not delete item: $($_.Name) - $($_.Exception.Message)"
            }
        }
        [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green
    } catch {
        Add-Content -Path $global:logFile -Value "Could not empty the Recycle Bin. Reason: $_.Exception.Message"
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

    # Download the installer
    Write-Host "Downloading Malwarebytes installer..."
    Invoke-WebRequest -Uri $url -OutFile $output

    # Check if the download was successful
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

    # Download the installer
    Write-Host "Downloading Intelligent Standby List Cleaner (ISLC) installer..."
    Invoke-WebRequest -Uri $url -OutFile $output

    # Check if the download was successful
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

    # List of registry values to modify
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

    # Modify existing or create missing registry values
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




# Define ANSI escape codes for colors and formatting
$BlueColor = "`e[34m"   # Blue color
$BoldText = "`e[1m"     # Bold text
$YellowColor = "`e[33m" # Yellow color
$ResetFormat = "`e[0m"  # Reset formatting

function Show-MainMenu {
    # Display the title
    Write-Host -ForegroundColor Blue -NoNewline "`nWelcome To the All Included Script`nby h4n1 - bdark`n"

    # Display the menu options
    Write-Host -ForegroundColor Yellow -NoNewline "`nEnter your choice:`n"
    Write-Host " Boost:" -ForegroundColor Blue
    Write-Host " 1. Clear Cache"
    Write-Host " 2. Intelligent standby list cleaner (ISLC)"
    Write-Host " DirectX:" -ForegroundColor Blue
    Write-Host " 3. DirectX Tweak"
    Write-Host " Security:" -ForegroundColor Blue
    Write-Host " 4. Install Malwarebytes"
    Write-Host " Internet:" -ForegroundColor Blue
    Write-Host " 5. Install IDM"
    Write-Host " Microsoft:" -ForegroundColor Blue
    Write-Host " 6. Install / Activate Windows"
    Write-Host " 7. Install / Activate Office"
    Write-Host " 8. Exit`n" -ForegroundColor Red
}

# Main script loop
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
        8 { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice. Please try again." }
    }
} while ($choice -ne 8)
