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

function Show-SubMenu {
    param (
        [string]$Title = 'Clear Cache Menu'
    )

    Write-Host " -------------------------"
    Write-Host " |     $Title     |"
    Write-Host " -------------------------"
    Write-Host " 1. Clean All (Recommended)"
    Write-Host " 2. Clear temporary files"
    Write-Host " 3. Clear browser history and cache"
    Write-Host " 4. Clear Recycle Bin"
    Write-Host " 5. Back to Main Menu"
    Write-Host
}

function Show-MainMenu {
    param (
        [string]$Title = 'Main Menu'
    )

    Write-Host " ========================="
    Write-Host " |     $Title     |"
    Write-Host " ========================="
    Write-Host " Boost:"
    Write-Host " 1. Clean All (Recommended)"
    Write-Host " Security:"
    Write-Host " 2. Install Malwarebytes"
    Write-Host " Internet:"
    Write-Host " 3. Install IDM"
    Write-Host " Microsoft:"
    Write-Host " 4. Install / Activate Windows"
    Write-Host " 5. Install / Activate Office"
    Write-Host " 6. Exit"
    Write-Host
}

function Check-LogFile {
    if (Test-Path -Path $global:logFile) {
        Write-Host "Log file has been generated at your desktop with the files that couldn't be deleted." -ForegroundColor Red
    }
}

do {
    Show-MainMenu
    $mainChoice = Read-Host 'Enter your choice'

    switch ($mainChoice) {
        1 {
            Clear-TempFiles
            Clear-BrowserCache
            Clear-RecycleBin
            Write-Host "All selected tasks - Done Cleaning" -ForegroundColor Green
            Check-LogFile
        }
        2 {
            Install-MB
        }
        3 {
            Run-IDM
        }
        4 {
            Activate-Windows
        }
        5 {
            Activate-Office
        }
        6 {
            Write-Host "Exiting..."
        }
        default {
            Write-Host "Invalid choice. Please try again."
        }
    }
} while ($mainChoice -ne 6)
