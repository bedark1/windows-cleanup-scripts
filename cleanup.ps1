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
    # Define the registry keys and values for DirectX tweak
    $regKey = "HKLM\SOFTWARE\Microsoft\DirectX"
    $regValues = @{
        "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE"="dword:00000001"
        "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS"="dword:00000001"
        "D3D12_RESOURCE_ALIGNMENT"="dword:00000001"
        "D3D11_MULTITHREADED"="dword:00000001"
        "D3D12_MULTITHREADED"="dword:00000001"
        "D3D11_DEFERRED_CONTEXTS"="dword:00000001"
        "D3D12_DEFERRED_CONTEXTS"="dword:00000001"
        "D3D11_ALLOW_TILING"="dword:00000001"
        "D3D11_ENABLE_DYNAMIC_CODEGEN"="dword:00000001"
        "D3D12_ALLOW_TILING"="dword:00000001"
        "D3D12_CPU_PAGE_TABLE_ENABLED"="dword:00000001"
        "D3D12_HEAP_SERIALIZATION_ENABLED"="dword:00000001"
        "D3D12_MAP_HEAP_ALLOCATIONS"="dword:00000001"
        "D3D12_RESIDENCY_MANAGEMENT_ENABLED"="dword:00000001"
    }

    # Check for administrative privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "You must have administrator rights to perform this action." -ForegroundColor Red
        return
    }

    Write-Host "DirectX Tweak - Applying registry modifications..." -ForegroundColor Yellow
    $failedItems = @()
    foreach ($value in $regValues.GetEnumerator()) {
        $name = $value.Key
        $data = $value.Value
        try {
            Set-ItemProperty -Path $regKey -Name $name -Value $data -ErrorAction Stop
            Write-Host "Registry value modified: $name" -ForegroundColor Green
        } catch {
            Write-Host "Failed to modify registry value: $name" -ForegroundColor Red
            $failedItems += $name
            Add-Content -Path $global:logFile -Value "Failed to modify registry value: $name - $($_.Exception.Message)"
        }
    }
    if ($failedItems.Count -eq 0) {
        Write-Host "DirectX Tweak - Registry modifications complete." -ForegroundColor Green
    } else {
        Write-Host "Failed to modify the following registry values:" -ForegroundColor Red
        foreach ($item in $failedItems) {
            Write-Host $item -ForegroundColor Red
        }
    }
}

function Show-MainMenu {
    Write-Host " Boost:"
    Write-Host " 1. Clear Cache"
    Write-Host " 2. Intelligent standby list cleaner (ISLC)"
    Write-Host " DirectX:"
    Write-Host " 3. DirectX Tweak"
    Write-Host " Security:"
    Write-Host " 4. Install Malwarebytes"
    Write-Host " Internet:"
    Write-Host " 5. Install IDM"
    Write-Host " Microsoft:"
    Write-Host " 6. Install / Activate Windows"
    Write-Host " 7. Install / Activate Office"
    Write-Host " 8. Exit"
    Write-Host
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

