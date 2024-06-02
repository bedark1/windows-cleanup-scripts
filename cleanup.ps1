function Clear-TempFiles {
    $tempPaths = @(
        "$env:windir\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )
    $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")

    Write-Host "TempFiles - Clearing" -ForegroundColor Yellow
    foreach ($path in $tempPaths) {
        Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            } catch {
                Add-Content -Path $logFile -Value "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
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
    $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")

    Write-Host "BrowserData - Clearing" -ForegroundColor Yellow
    foreach ($path in $browserPaths) {
        Get-ChildItem -Path $path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            } catch {
                Add-Content -Path $logFile -Value "Could not remove item: $($_.FullName) - $($_.Exception.Message)"
            }
        }
    }
    Write-Host "BrowserData - Done Cleaning" -ForegroundColor Green
}

function Clear-RecycleBin {
    $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")

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
                Add-Content -Path $logFile -Value "Could not delete item: $($_.Name) - $($_.Exception.Message)"
            }
        }
        [Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green
    } catch {
        Add-Content -Path $logFile -Value "Could not empty the Recycle Bin. Reason: $_.Exception.Message"
    }
}

function Run-IDM {
    $scriptUrl = "https://massgrave.dev/ias"
    $command = "irm $scriptUrl | iex"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $command -Verb RunAs
    Write-Host "IDM cleanup script executed." -ForegroundColor Green
}

function Show-Menu {
    param (
        [string]$Title = 'Cleanup Menu'
    )

    Write-Host " -------------------------"
    Write-Host " |     $Title     |"
    Write-Host " -------------------------"
    Write-Host " 1. Clean All (Recommended)"
    Write-Host " 2. Clearing temporary files"
    Write-Host " 3. Clearing browser history and cache"
    Write-Host " 4. Clearing Recycle Bin"
    Write-Host " 5. Run IDM"
    Write-Host " 6. Exit"
    Write-Host
}

do {
    Show-Menu
    $choice = Read-Host 'Enter your choice'

    switch ($choice) {
        1 {
            Clear-TempFiles
            Clear-BrowserCache
            Clear-RecycleBin
            Write-Host "All selected tasks - Done Cleaning" -ForegroundColor Green
            $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")
            if (Test-Path -Path $logFile) {
                Write-Host "Log file has been generated at your desktop with the files that couldn't be deleted." -ForegroundColor Red
            }
        }
        2 {
            Clear-TempFiles
            Write-Host "Temporary files - Done Cleaning" -ForegroundColor Green
            $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")
            if (Test-Path -Path $logFile) {
                Write-Host "Log file has been generated at your desktop with the files that couldn't be deleted." -ForegroundColor Red
            }
        }
        3 {
            Clear-BrowserCache
            Write-Host "Browser cache - Done Cleaning" -ForegroundColor Green
            $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")
            if (Test-Path -Path $logFile) {
                Write-Host "Log file has been generated at your desktop with the files that couldn't be deleted." -ForegroundColor Red
            }
        }
        4 {
            Clear-RecycleBin
            Write-Host "Recycle Bin - Done Cleaning" -ForegroundColor Green
            $logFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CleanupLog.txt")
            if (Test-Path -Path $logFile) {
                Write-Host "Log file has been generated at your desktop with the files that couldn't be deleted." -ForegroundColor Red
            }
        }
        5 {
            Run-IDM
        }
        6 {
            Write-Host "Exiting..."
        }
        default {
            Write-Host "Invalid choice. Please try again."
        }
    }
} while ($choice -ne 6)
