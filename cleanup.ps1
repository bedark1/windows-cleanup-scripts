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

function Optimize-Performance-All {
    Disable-PagingFile
    Apply-RegistryTweaks
    Disable-UnnecessaryServices
    Adjust-GraphicsAndMultimediaSettings
    Disable-WindowsUpdates
    Remove-WindowsBloatware
    Disable-UnnecessaryStartupPrograms
}

function Optimize-Performance {
    function Disable-PagingFile {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "c:\pagefile.sys 0 0" -ErrorAction Stop
            Write-Host "Paging file disabled successfully."
        } catch {
            Handle-Error "Failed to disable paging file. $_"
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
            Write-Host "Registry tweaks applied successfully."
        } catch {
            Handle-Error "Failed to apply registry tweaks. $_"
        }
    }

    function Disable-UnnecessaryServices {
        $services = @("SysMain", "WSearch", "DiagTrack", "dmwappushservice", "WMPNetworkSvc")
        foreach ($service in $services) {
            try {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                Write-Host "$service service disabled successfully."
            } catch {
                Handle-Error "Failed to disable $service service. $_"
            }
        }
    }

    function Adjust-GraphicsAndMultimediaSettings {
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Multimedia\Audio" -Name "DisableProtectedAudioDG" -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Direct3D" -Name "ForceDriverVersion" -Value "9.18.13.2049" -ErrorAction Stop
            Write-Host "Graphics and multimedia settings adjusted successfully."
        } catch {
            Handle-Error "Failed to adjust graphics and multimedia settings. $_"
        }
    }

    function Disable-WindowsUpdates {
        try {
            Stop-Service -Name wuauserv -Force -ErrorAction Stop
            Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
            Write-Host "Windows Updates disabled successfully."
        } catch {
            Handle-Error "Failed to disable Windows Updates. $_"
        }
    }

    function Remove-WindowsBloatware {
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
            try {
                Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction Stop
                Write-Host "$app removed successfully."
            } catch {
                Handle-Error "Failed to remove $app. $_"
            }
        }
    }

    function Disable-UnnecessaryStartupPrograms {
        $startupItems = @(
            "OneDrive",
            "Skype",
            "Spotify",
            "Cortana"
        )
        foreach ($item in $startupItems) {
            try {
                Stop-Process -Name $item -Force -ErrorAction Stop
                Write-Host "$item disabled successfully."
            } catch {
                Handle-Error "Failed to disable $item. $_"
            }
        }
    }

    function Revert-AllChanges {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "c:\pagefile.sys" -ErrorAction Stop
            Start-Service -Name wuauserv -ErrorAction Stop
            Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
            foreach ($service in @("SysMain", "WSearch", "DiagTrack", "dmwappushservice", "WMPNetworkSvc")) {
                Start-Service -Name $service -ErrorAction Stop
                Set-Service -Name $service -StartupType Automatic -ErrorAction Stop
            }
            Write-Host "All changes reverted successfully."
        } catch {
            Handle-Error "Failed to revert changes. $_"
        }
    }

    function Show-OptimizeMenu {
        Write-Host "`nOptimize Windows Performance:`" -ForegroundColor Yellow
        Write-Host "1. Optimize Windows Performance (All)"
        Write-Host "2. Disable Paging File"
        Write-Host "3. Apply Registry Tweaks"
        Write-Host "4. Disable Unnecessary Services"
        Write-Host "5. Adjust Graphics and Multimedia Settings"
        Write-Host "6. Disable Windows Updates"
        Write-Host "7. Remove Windows Bloatware"
        Write-Host "8. Disable Unnecessary Startup Programs"
        Write-Host "9. Revert All Changes"
        Write-Host "10. Back to Main Menu`n"
    }

    do {
        Show-OptimizeMenu
        $optChoice = Read-Host "Enter your choice"

        switch ($optChoice) {
            1 { Optimize-Performance-All }
            2 { Disable-PagingFile }
            3 { Apply-RegistryTweaks }
            4 { Disable-UnnecessaryServices }
            5 { Adjust-GraphicsAndMultimediaSettings }
            6 { Disable-WindowsUpdates }
            7 { Remove-WindowsBloatware }
            8 { Disable-UnnecessaryStartupPrograms }
            9 { Revert-AllChanges }
            10 { Write-Host "Returning to Main Menu..."; break }
            default { Write-Host "Invalid choice. Please try again." }
        }
    } while ($optChoice -ne 10)
}

function Show-MainMenu {
    Write-Host -ForegroundColor Blue -NoNewline "`nWelcome To the All Included Script`nby h4n1 - bdark`n"
    Write-Host -ForegroundColor Yellow -NoNewline "`nEnter your choice:`n"
    Write-Host " Boost:" -ForegroundColor Blue
    Write-Host " 1. Clear Cache"
    Write-Host " 2. Optimize Windows Performance (All)"
    Write-Host " 3. Intelligent standby list cleaner (ISLC)`n"
}

function Main-Menu {
    do {
        Show-MainMenu
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            1 { Clear-TempFiles; Clear-BrowserCache; Clear-RecycleBin }
            2 { Optimize-Performance }
            3 { Install-ISLC }
            default { Write-Host "Invalid choice. Please try again." }
        }
    } while ($choice -ne 3)
}

Main-Menu
