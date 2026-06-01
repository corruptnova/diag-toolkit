#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive diagnostics collector for crash, driver, performance, and hardware issues.
.DESCRIPTION
    Collects event logs, minidumps, driver info, SMART data, WER reports, system info,
    reliability history, storage health, thermal data, and more into a timestamped ZIP.
.NOTES
    Run as Administrator for full data collection.
    Some checks require third-party tools placed in the .\tools\ subdirectory:
      - smartmontools (smartctl.exe) for SMART disk health
    All other checks use built-in Windows tools only.
#>

[CmdletBinding()]
param(
    [int]$EventLogHours  = 72,
    [switch]$SkipMinidumps,
    [switch]$SkipSMART,
    [switch]$SkipNetworkInfo,
    [string]$OutputDir   = "$env:USERPROFILE\Desktop"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Elevation check ───────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "⚠  NOT running as Administrator. Some data collection will be limited."
    Write-Warning "   Re-run from an elevated PowerShell prompt for full diagnostics."
}

# ── Setup workspace ───────────────────────────────────────────────────────────
$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$hostname = $env:COMPUTERNAME
$workDir  = Join-Path $env:TEMP "DiagCollect_${hostname}_${stamp}"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$toolsDir = Join-Path $PSScriptRoot "tools"
$logFile  = Join-Path $workDir "collection_log.txt"

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format 'HH:mm:ss'
    $line = "[$ts][$Level] $Msg"
    $line | Tee-Object -FilePath $logFile -Append | Write-Host -ForegroundColor $(
        switch ($Level) { "WARN" {"Yellow"} "ERROR" {"Red"} "OK" {"Green"} default {"Cyan"} })
}

function Save-Output {
    param([string]$File, [scriptblock]$Action)
    try {
        $result = & $Action 2>&1
        $result | Out-File -FilePath (Join-Path $workDir $File) -Encoding UTF8 -Force
        Write-Log "  Saved: $File" "OK"
    } catch {
        Write-Log "  Failed: $File — $_" "WARN"
    }
}

Write-Log "=== Diagnostics Collector starting — $stamp ==="
Write-Log "Host: $hostname | Admin: $isAdmin | PS: $($PSVersionTable.PSVersion)"
Write-Log "Output will be zipped to: $OutputDir"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. SYSTEM OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [1/10] System Overview ──────────────────────────────────────────"

Save-Output "01_system_info.txt" {
    "=== SYSTEM INFO ===" | Out-String
    Get-ComputerInfo | Select-Object `
        CsName, CsManufacturer, CsModel, CsSystemType,
        WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture,
        CsProcessors, CsTotalPhysicalMemory,
        BiosManufacturer, BiosVersion, BiosSMBIOSBIOSVersion, BiosReleaseDate,
        OsInstallDate, OsLastBootUpTime | Format-List
    ""
    "=== UPTIME ===" | Out-String
    $os = Get-WmiObject Win32_OperatingSystem
    $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
    "Last boot : $($os.ConvertToDateTime($os.LastBootUpTime))"
    "Uptime    : $([math]::Floor($uptime.TotalHours))h $($uptime.Minutes)m"
}

Save-Output "01b_cpu_info.txt" {
    "=== CPU ===" | Out-String
    Get-WmiObject Win32_Processor | Select-Object Name, Manufacturer,
        MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors,
        L2CacheSize, L3CacheSize, CurrentClockSpeed,
        LoadPercentage | Format-List
    ""
    "=== MEMORY MODULES ===" | Out-String
    Get-WmiObject Win32_PhysicalMemory | Select-Object Tag, Manufacturer,
        PartNumber, SerialNumber, Capacity, Speed, ConfiguredClockSpeed,
        MemoryType, SMBIOSMemoryType | Format-Table -AutoSize
}

Save-Output "01c_gpu_info.txt" {
    "=== GPU(s) ===" | Out-String
    Get-WmiObject Win32_VideoController | Select-Object Name, AdapterRAM,
        DriverVersion, DriverDate, VideoProcessor,
        CurrentHorizontalResolution, CurrentVerticalResolution,
        CurrentRefreshRate, AdapterDACType | Format-List
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. EVENT LOGS — Errors/Criticals
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [2/10] Event Logs (last $EventLogHours hours) ───────────────────"

$since = (Get-Date).AddHours(-$EventLogHours)

$eventLogs = @(
    @{Name="System";      File="02a_events_system.txt"},
    @{Name="Application"; File="02b_events_application.txt"},
    @{Name="Security";    File="02c_events_security_warn.txt"}
)

foreach ($el in $eventLogs) {
    $elName = $el.Name
    $elFile = $el.File
    Save-Output $elFile {
        try {
            $level = if ($elName -eq "Security") { @(2,3) } else { @(1,2,3) }
            Get-WinEvent -FilterHashtable @{
                LogName   = $elName
                Level     = $level
                StartTime = $since
            } -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated -Descending |
            Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap
        } catch {
            "Could not read ${elName} log: $_"
        }
    }
}

# Hardware events specifically
Save-Output "02d_events_hardware.txt" {
    "=== WHEA Hardware Error Events ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=$since
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'WHEA|disk|volmgr|ntfs|storport|iaStorV' } |
        Sort-Object TimeCreated -Descending |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap
    } catch { "No WHEA events or access denied." }
    ""
    "=== Kernel-Power Events ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; StartTime=$since
        } -ErrorAction SilentlyContinue |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, Message -Wrap
    } catch { "No Kernel-Power events." }
}

# TDR / GPU driver timeout events
Save-Output "02f_events_tdr_gpu.txt" {
    "=== GPU TDR (Display Driver Timeout/Reset) Events ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=$since
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'nvlddmkm|atikmpag|igfx|dxgkrnl|display' -or
                       ($_.Id -in @(4101,4117,1000,13,14) -and $_.ProviderName -match 'Microsoft-Windows-DisplayPort') } |
        Sort-Object TimeCreated -Descending |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap
    } catch { "No TDR events found or access denied." }
    ""
    "=== Dxgkrnl critical/error events ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Microsoft-Windows-Kernel-PnP'; StartTime=$since
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'display|video|GPU|render' } |
        Sort-Object TimeCreated -Descending | Select-Object -First 20 |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, Message -Wrap
    } catch {}
}

# Reliability Monitor (RacTask)
Save-Output "02e_reliability_history.txt" {
    "=== Reliability Monitor History (last 30 days) ===" | Out-String
    try {
        $rel = Get-WmiObject -Namespace root\cimv2 -Class Win32_ReliabilityRecords -ErrorAction SilentlyContinue
        if ($rel) {
            $rel | Sort-Object TimeGenerated -Descending | Select-Object -First 200 |
            Format-Table -AutoSize TimeGenerated, SourceName, EventIdentifier, Message -Wrap
        } else { "Reliability records not available." }
    } catch { "Could not query reliability records: $_" }
}

# USB / peripheral errors
Save-Output "02g_events_usb.txt" {
    "=== USB Error/Disconnect Events ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=$since
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'usbhub|usbport|usbxhci|usbaudio|HidUsb' -and $_.Level -le 3 } |
        Sort-Object TimeCreated -Descending | Select-Object -First 50 |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap
    } catch { "No USB error events found." }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. CRASH DUMPS & WER
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [3/10] Crash Dumps & WER Reports ───────────────────────────────"

if (-not $SkipMinidumps) {
    $dumpDir  = "$env:SystemRoot\Minidump"
    $dumpDest = Join-Path $workDir "minidumps"
    New-Item -ItemType Directory $dumpDest -Force | Out-Null

    if (Test-Path $dumpDir) {
        $dumps = Get-ChildItem "$dumpDir\*.dmp" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 20
        if ($dumps) {
            Write-Log "  Found $($dumps.Count) minidump(s) — copying most recent 20"
            $dumps | Copy-Item -Destination $dumpDest -ErrorAction SilentlyContinue
            $dumps | Select-Object Name, LastWriteTime, @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} |
                Format-Table | Out-File (Join-Path $workDir "03a_minidump_list.txt") -Encoding UTF8
        } else { "No .dmp files found in $dumpDir" | Out-File (Join-Path $workDir "03a_minidump_list.txt") }
    } else { "Minidump directory not found: $dumpDir" | Out-File (Join-Path $workDir "03a_minidump_list.txt") }

    # Memory.dmp (full/kernel dump)
    $memDump = "$env:SystemRoot\MEMORY.DMP"
    if (Test-Path $memDump) {
        $sz = (Get-Item $memDump).Length / 1MB
        Write-Log "  MEMORY.DMP found ($([math]::Round($sz,1)) MB) — logging metadata only (too large to copy)"
        "MEMORY.DMP found: $memDump`nSize: $([math]::Round($sz,1)) MB`nLast modified: $((Get-Item $memDump).LastWriteTime)" |
            Out-File (Join-Path $workDir "03b_memory_dump_info.txt") -Encoding UTF8
    }

    # Capture crash dump registry config
    $dumpConfig = Join-Path $workDir "03a2_dump_settings.txt"
    "=== Crash Dump Configuration ===" | Out-File $dumpConfig -Encoding UTF8
    try {
        $crashCtl = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction Stop
        @(
            "DumpFile         : $($crashCtl.DumpFile)",
            "CrashDumpEnabled : $($crashCtl.CrashDumpEnabled) $(switch ($crashCtl.CrashDumpEnabled) { 0 {'(None)'} 1 {'(Complete)'} 2 {'(Kernel)'} 3 {'(Small/Minidump)'} 7 {'(Automatic)'} default {'(Unknown)'} })",
            "MiniDumpDir      : $($crashCtl.MiniDumpDir)",
            "AutoReboot       : $($crashCtl.AutoReboot)",
            "Overwrite        : $($crashCtl.Overwrite)"
        ) | Out-File $dumpConfig -Append -Encoding UTF8
    } catch {
        "Could not read CrashControl registry: $_" | Out-File $dumpConfig -Append -Encoding UTF8
    }

    Write-Log "  Saved minidumps" "OK"
} else { Write-Log "  Minidumps skipped (user flag)" "WARN" }

# WER (Windows Error Reporting) reports
Save-Output "03c_wer_reports.txt" {
    "=== Windows Error Reporting Fault Buckets (Application) ===" | Out-String
    $werPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive",
        "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue",
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    )
    foreach ($wp in $werPaths) {
        if (Test-Path $wp) {
            "--- $wp ---" | Out-String
            Get-ChildItem $wp -Recurse -Filter "Report.wer" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 30 | ForEach-Object {
                    $_.FullName | Out-String
                    Select-String -Path $_.FullName -Pattern "EventName|FriendlyEventName|AppName|AppPath|ModName|sig\[0\]" |
                        Select-Object -ExpandProperty Line
                    "---"
                }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. DRIVER INFORMATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [4/10] Driver Information ───────────────────────────────────────"

Save-Output "04a_drivers_all.txt" {
    "=== All Signed Drivers ===" | Out-String
    Get-WmiObject Win32_PnPSignedDriver |
        Sort-Object DeviceName |
        Format-Table -AutoSize DeviceName, DriverVersion, DriverDate, Manufacturer, IsSigned, DeviceID -Wrap
}

Save-Output "04b_drivers_problem.txt" {
    "=== PnP Devices with Error/Problem Status ===" | Out-String
    Get-WmiObject Win32_PnPEntity |
        Where-Object { $_.ConfigManagerErrorCode -ne 0 } |
        Select-Object Name, DeviceID, ConfigManagerErrorCode,
            @{N='ErrorMeaning';E={
                switch ($_.ConfigManagerErrorCode) {
                    1  {"Device not configured correctly"}
                    2  {"Windows cannot load driver"}
                    3  {"Driver may be corrupted"}
                    9  {"Reporting an IRQ in use by another device"}
                    10 {"Cannot start (Code 10)"}
                    12 {"Cannot find enough free resources"}
                    14 {"Restart required"}
                    18 {"Reinstall drivers"}
                    19 {"Registry corrupt"}
                    21 {"Removing device"}
                    22 {"Device disabled"}
                    24 {"Device not present"}
                    28 {"Drivers not installed"}
                    29 {"Disabled — firmware did not provide resources"}
                    31 {"Device not working — driver may be incompatible"}
                    32 {"Driver service start disabled"}
                    33 {"Cannot determine which resources required"}
                    34 {"Cannot use IRQ resource"}
                    35 {"Firmware did not provide BIOS resources"}
                    36 {"IRQ translation failed"}
                    37 {"Driver returned failure on load"}
                    38 {"Driver reloaded (prev instance still in memory)"}
                    39 {"Driver corrupted or missing"}
                    40 {"Service key access failure"}
                    41 {"Driver load failed (no matching devices)"}
                    42 {"Duplicate device"}
                    43 {"Device failure reported"}
                    44 {"Application blocked driver"}
                    45 {"No longer connected"}
                    46 {"Not available (system booting)"}
                    47 {"Registry exceeded size limit"}
                    48 {"Driver blocked — incompatible"}
                    49 {"Device console not started"}
                    52 {"Unsigned driver"}
                    default {"Unknown error code $($_.ConfigManagerErrorCode)"}
                }
            }} |
        Format-Table -AutoSize -Wrap
}

Save-Output "04c_driver_verifier_status.txt" {
    "=== Driver Verifier Status ===" | Out-String
    verifier /query 2>&1
    ""
    "=== Driver Verifier Settings ===" | Out-String
    verifier /querysettings 2>&1
}

Save-Output "04d_drivers_unsigned.txt" {
    "=== Unsigned / Verification-Failed Drivers ===" | Out-String
    Get-WmiObject Win32_PnPSignedDriver |
        Where-Object { $_.IsSigned -eq $false -or $_.IsSigned -eq $null } |
        Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer, DeviceID |
        Format-Table -AutoSize
    ""
    "=== sigverif log (if exists) ===" | Out-String
    $sigLog = "$env:WINDIR\system32\sigverif.txt"
    if (Test-Path $sigLog) { Get-Content $sigLog } else { "sigverif.txt not found." }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. STORAGE HEALTH
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [5/10] Storage Health ───────────────────────────────────────────"

Save-Output "05a_disk_info.txt" {
    "=== Physical Disks ===" | Out-String
    Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType,
        BusType, OperationalStatus, HealthStatus,
        @{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} |
        Format-Table -AutoSize
    ""
    "=== Logical Disks ===" | Out-String
    Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, FileSystem, VolumeName,
            @{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}},
            @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}},
            @{N='UsedPct';E={if ($_.Size -gt 0) { [math]::Round(100*($_.Size-$_.FreeSpace)/$_.Size,1) } else { 0 }}} |
        Format-Table -AutoSize
    ""
    "=== Volume Shadow Copies ===" | Out-String
    vssadmin list shadows 2>&1 | Select-Object -First 40
}

Save-Output "05b_disk_storage_spaces.txt" {
    "=== Storage Spaces / Storage Pools ===" | Out-String
    try {
        Get-StoragePool | Format-Table -AutoSize FriendlyName, HealthStatus, OperationalStatus, IsPrimordial
        Get-VirtualDisk -ErrorAction SilentlyContinue | Format-Table -AutoSize FriendlyName, HealthStatus, OperationalStatus, ResiliencySettingName
    } catch { "Storage Spaces not configured or access denied." }
}

# SMART via Windows built-in (limited)
Save-Output "05c_disk_reliability_wmi.txt" {
    "=== WMI Disk Reliability Counters (MSStorageDriver_FailurePredictData) ===" | Out-String
    try {
        $smartData = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictData -ErrorAction Stop
        $smartStatus = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop
        $smartStatus | Select-Object InstanceName,
            @{N='PredictFailure';E={$_.PredictFailure}},
            @{N='Reason';E={$_.Reason}} | Format-Table -AutoSize
    } catch { "WMI SMART data unavailable: $_" }
    ""
    "=== chkdsk-style disk errors (System eventlog) ===" | Out-String
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'disk|ntfs|fastfat|cdrom|volmgr' } |
        Sort-Object TimeCreated -Descending | Select-Object -First 50 |
        Format-Table -AutoSize TimeCreated, Id, ProviderName, Message -Wrap
}

# smartctl (optional 3rd party)
if (-not $SkipSMART) {
    $smartctl = Join-Path $toolsDir "smartctl.exe"
    if (Test-Path $smartctl) {
        Write-Log "  smartctl found — running SMART health checks"
        $smartOut = Join-Path $workDir "05d_smart_full.txt"
        "=== SMART Data via smartmontools ===" | Out-File $smartOut -Encoding UTF8
        $drives = 0..9
        foreach ($d in $drives) {
            $result = & $smartctl -a "/dev/pd$d" -d auto 2>&1
            if ($result -match 'No such device|Open failed|Unable to detect|Smartctl open device') { continue }
            "`n=== /dev/pd$d ===" | Out-File $smartOut -Append -Encoding UTF8
            $result | Out-File $smartOut -Append -Encoding UTF8
        }
        Write-Log "  SMART data saved" "OK"
    } else {
        "smartctl.exe not found in .\tools\  — place smartmontools here for full SMART data.`nDownload: https://www.smartmontools.org/wiki/Download" |
            Out-File (Join-Path $workDir "05d_smart_not_available.txt") -Encoding UTF8
        Write-Log "  smartctl not found in .\tools\ — basic WMI SMART only" "WARN"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. PERFORMANCE & THERMAL
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [6/10] Performance & Thermal ────────────────────────────────────"

Save-Output "06a_performance_snapshot.txt" {
    "=== CPU Performance (current) ===" | Out-String
    $cpuLoad = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    "CPU Load: $cpuLoad%"
    ""
    "=== Memory Usage ===" | Out-String
    $os = Get-WmiObject Win32_OperatingSystem
    $totalMB   = [math]::Round($os.TotalVisibleMemorySize/1KB, 0)
    $freeMB    = [math]::Round($os.FreePhysicalMemory/1KB, 0)
    $usedMB    = $totalMB - $freeMB
    $usedPct   = [math]::Round(100 * $usedMB / $totalMB, 1)
    "Total: $totalMB MB | Used: $usedMB MB ($usedPct%) | Free: $freeMB MB"
    ""
    "=== Top 20 Processes by CPU ===" | Out-String
    Get-Process -ErrorAction SilentlyContinue |
        ForEach-Object {
            $cpuSec = try {
                if ($_.CPU -is [TimeSpan]) { [math]::Round($_.CPU.TotalSeconds, 1) }
                elseif ($null -ne $_.CPU)  { [math]::Round([double]$_.CPU, 1) }
                else                       { 0.0 }
            } catch { 0.0 }
            $startT = try { $_.StartTime } catch { 'N/A' }
            [PSCustomObject]@{
                Id          = $_.Id
                ProcessName = $_.ProcessName
                CpuSec      = $cpuSec
                WS_MB       = [math]::Round($_.WorkingSet64/1MB, 1)
                VM_MB       = [math]::Round($_.VirtualMemorySize64/1MB, 1)
                Handles     = $_.Handles
                StartTime   = $startT
            }
        } | Sort-Object CpuSec -Descending | Select-Object -First 20 |
        Format-Table -AutoSize Id, ProcessName,
            @{N='CPU(s)';E={$_.CpuSec}},
            @{N='WS(MB)';E={$_.WS_MB}},
            @{N='VM(MB)';E={$_.VM_MB}},
            Handles, StartTime
    ""
    "=== Top 20 Processes by Memory ===" | Out-String
    Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 20 |
        Format-Table -AutoSize Id, ProcessName,
            @{N='WS(MB)';E={[math]::Round($_.WorkingSet64/1MB,1)}},
            @{N='PM(MB)';E={[math]::Round($_.PrivateMemorySize64/1MB,1)}}
}

Save-Output "06b_thermal_battery.txt" {
    "=== Thermal Zones ===" | Out-String
    try {
        Get-WmiObject -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction Stop |
            Select-Object InstanceName,
                @{N='TempC';E={[math]::Round(($_.CurrentTemperature/10)-273.15,1)}},
                @{N='CritTempC';E={[math]::Round(($_.CriticalTripPoint/10)-273.15,1)}} |
            Format-Table -AutoSize
    } catch { "Thermal zone data unavailable via WMI: $_" }
    ""
    "=== Battery Info ===" | Out-String
    $bat = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue
    if ($bat) {
        $bat | Select-Object Name, DeviceID, EstimatedChargeRemaining,
            BatteryStatus, DesignCapacity, FullChargeCapacity,
            @{N='WearPct';E={
                if ($_.DesignCapacity -and $_.DesignCapacity -gt 0 -and $_.FullChargeCapacity) {
                    [math]::Round(100*(1-$_.FullChargeCapacity/$_.DesignCapacity),1)
                } else { "N/A" }
            }} | Format-List
    } else { "No battery found (desktop system)." }
    ""
    "=== Battery Report (powercfg) ===" | Out-String
    $batRpt = Join-Path $env:TEMP "battery_report_diag.html"
    powercfg /batteryreport /output $batRpt 2>&1
    if (Test-Path $batRpt) {
        Copy-Item $batRpt (Join-Path $workDir "06c_battery_report.html") -Force
        "Battery report saved as 06c_battery_report.html"
        Remove-Item $batRpt -Force -ErrorAction SilentlyContinue
    }
}

# Power/sleep diagnostics
Save-Output "06d_power_energy.txt" {
    "=== Power Configuration ===" | Out-String
    powercfg /list 2>&1
    ""
    powercfg /query 2>&1 | Select-Object -First 80
    ""
    "=== Sleep/Hibernate Diagnostics ===" | Out-String
    powercfg /sleepstudy /duration 7 /output (Join-Path $env:TEMP "sleepstudy_diag.html") 2>&1
    if (Test-Path (Join-Path $env:TEMP "sleepstudy_diag.html")) {
        Copy-Item (Join-Path $env:TEMP "sleepstudy_diag.html") (Join-Path $workDir "06e_sleep_study.html")
        "Sleep study saved as 06e_sleep_study.html"
    }
    ""
    "=== Wake Source History ===" | Out-String
    powercfg /waketimers 2>&1
    powercfg /lastwake 2>&1
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. SYSTEM FILE & INTEGRITY CHECKS (non-destructive, output only)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [7/10] System Integrity Info ────────────────────────────────────"

Save-Output "07a_sfc_cbs_log.txt" {
    "=== SFC Log (CBS.log last 500 lines) ===" | Out-String
    $cbs = "$env:SystemRoot\Logs\CBS\CBS.log"
    if (Test-Path $cbs) {
        "NOTE: Run 'sfc /scannow' manually if integrity errors are suspected."
        ""
        Get-Content $cbs -Tail 500 -ErrorAction SilentlyContinue
    } else { "CBS.log not found." }
}

Save-Output "07a2_chkdsk_log.txt" {
    "=== chkdsk Event Log Results (Event 26226 / Wininit) ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='Application'; ProviderName='Microsoft-Windows-Wininit'
        } -ErrorAction SilentlyContinue | Select-Object -First 10 |
        Format-Table -AutoSize TimeCreated, Id, Message -Wrap
    } catch { "No chkdsk (Wininit) results in event log." }
    ""
    "=== chkdsk scheduled drives ===" | Out-String
    chkntfs /? 2>&1 | Select-Object -First 3
    Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $drive = $_.DeviceID
            $result = chkntfs $drive 2>&1
            "$drive : $result"
        }
}

Save-Output "07b_dism_log.txt" {
    "=== DISM Log (last 300 lines) ===" | Out-String
    $dismLog = "$env:SystemRoot\Logs\DISM\dism.log"
    if (Test-Path $dismLog) {
        Get-Content $dismLog -Tail 300 -ErrorAction SilentlyContinue
    } else { "DISM log not found." }
}

Save-Output "07c_wer_fault_buckets.txt" {
    "=== Application Fault Buckets (Event 1001) ===" | Out-String
    Get-WinEvent -FilterHashtable @{
        LogName='Application'; Id=1001; StartTime=(Get-Date).AddDays(-30)
    } -ErrorAction SilentlyContinue |
    Format-Table -AutoSize TimeCreated, ProviderName, Message -Wrap
    ""
    "=== App Hang Events (Event 1002) ===" | Out-String
    Get-WinEvent -FilterHashtable @{
        LogName='Application'; Id=1002; StartTime=(Get-Date).AddDays(-30)
    } -ErrorAction SilentlyContinue |
    Format-Table -AutoSize TimeCreated, ProviderName, Message -Wrap
    ""
    "=== App Crash Events (Event 1000) ===" | Out-String
    Get-WinEvent -FilterHashtable @{
        LogName='Application'; Id=1000; StartTime=(Get-Date).AddDays(-30)
    } -ErrorAction SilentlyContinue |
    Format-Table -AutoSize TimeCreated, ProviderName, Message -Wrap
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. NETWORK DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────
if (-not $SkipNetworkInfo) {
    Write-Log "── [8/10] Network Information ──────────────────────────────────────"

    Save-Output "08a_network_adapters.txt" {
        "=== Network Adapters ===" | Out-String
        Get-NetAdapter | Format-Table -AutoSize Name, InterfaceDescription, Status,
            MacAddress, LinkSpeed, MediaType
        ""
        "=== IP Configuration ===" | Out-String
        Get-NetIPConfiguration | Format-List
        ""
        "=== DNS Client Cache ===" | Out-String
        Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 30 |
            Format-Table -AutoSize Entry, Name, Type, TimeToLive, Data
    }

    Save-Output "08b_network_connections.txt" {
        "=== Active TCP Connections ===" | Out-String
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Sort-Object RemotePort |
            ForEach-Object {
                $proc = try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { "N/A" }
                [PSCustomObject]@{
                    LocalAddress  = "$($_.LocalAddress):$($_.LocalPort)"
                    RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
                    State         = $_.State
                    PID           = $_.OwningProcess
                    Process       = $proc
                }
            } | Format-Table -AutoSize
        ""
        "=== Listening Ports ===" | Out-String
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            ForEach-Object {
                $proc = try { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { "N/A" }
                [PSCustomObject]@{
                    LocalAddress = "$($_.LocalAddress):$($_.LocalPort)"
                    PID          = $_.OwningProcess
                    Process      = $proc
                }
            } | Sort-Object LocalAddress | Format-Table -AutoSize
    }

    Save-Output "08c_network_stats.txt" {
        "=== Adapter Statistics ===" | Out-String
        Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Format-Table -AutoSize
        ""
        "=== WLAN Info ===" | Out-String
        netsh wlan show all 2>&1 | Select-Object -First 80
        ""
        "=== Network Errors (Event Log) ===" | Out-String
        Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=(Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'tcpip|dhcp|ndis|netft|nics' -and $_.Level -le 3 } |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, ProviderName, Message -Wrap
    }
} else { Write-Log "  Network info skipped (user flag)" "WARN" }

# ─────────────────────────────────────────────────────────────────────────────
# 9. INSTALLED SOFTWARE & STARTUP
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [9/10] Software, Startup & Services ─────────────────────────────"

Save-Output "09a_installed_software.txt" {
    "=== Installed Software (Add/Remove Programs) ===" | Out-String
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $regPaths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ -ne $null -and ($_.PSObject.Properties.Name -contains 'DisplayName') -and $_.DisplayName } |
        Select-Object DisplayName,
            @{N='DisplayVersion'; E={ if ($_.PSObject.Properties.Name -contains 'DisplayVersion') { $_.DisplayVersion } else { '' } }},
            @{N='Publisher';      E={ if ($_.PSObject.Properties.Name -contains 'Publisher')      { $_.Publisher }      else { '' } }},
            @{N='InstallDate';    E={ if ($_.PSObject.Properties.Name -contains 'InstallDate')    { $_.InstallDate }    else { '' } }} |
        Sort-Object DisplayName |
        Format-Table -AutoSize
}

Save-Output "09b_startup_items.txt" {
    "=== Startup Programs (Task Manager / Run keys) ===" | Out-String
    Get-CimInstance Win32_StartupCommand | Format-Table -AutoSize Caption, Command, Location, User
    ""
    "=== Scheduled Tasks (non-Microsoft, enabled) ===" | Out-String
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch '^\\Microsoft' -and $_.State -eq 'Ready' } |
        Select-Object TaskName, TaskPath, State,
            @{N='NextRun';E={($_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).NextRunTime}} |
        Format-Table -AutoSize
}

Save-Output "09c_services.txt" {
    "=== Stopped Services (that should be running) ===" | Out-String
    Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
        Format-Table -AutoSize Name, DisplayName, Status, StartType
    ""
    "=== All Services ===" | Out-String
    Get-Service | Sort-Object StartType, Status |
        Format-Table -AutoSize Name, DisplayName, Status, StartType
}

# ─────────────────────────────────────────────────────────────────────────────
# 10. ADVANCED / SUPPLEMENTAL
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "── [10/10] Advanced & Supplemental ────────────────────────────────"

# msinfo32 — direct write (async-safe)
"=== msinfo32 System Report ===" | Out-File (Join-Path $workDir "10a_msinfo32.txt") -Encoding UTF8
$nfoFile = Join-Path $env:TEMP "sysinfo_diag.nfo"
$txtFile = Join-Path $env:TEMP "sysinfo_diag.txt"
Remove-Item $txtFile -ErrorAction SilentlyContinue
Remove-Item $nfoFile -ErrorAction SilentlyContinue

# msinfo32 is async — use Start-Process -Wait to block until it finishes
Write-Log "  Running msinfo32 (may take 30-60s)..."
try {
    $proc = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report `"$txtFile`"" -PassThru -WindowStyle Hidden
    # Wait up to 90 seconds, polling every 2s
    $waited = 0
    while (-not (Test-Path $txtFile) -and $waited -lt 90) {
        Start-Sleep 2; $waited += 2
    }
    # Give it a couple extra seconds to finish writing
    Start-Sleep 3
    if (-not $proc.HasExited) { $proc.Kill() }
} catch {
    "msinfo32 launch failed: $_" | Out-File (Join-Path $workDir "10a_msinfo32.txt") -Append -Encoding UTF8
}

if (Test-Path $txtFile) {
    Get-Content $txtFile | Out-File (Join-Path $workDir "10a_msinfo32.txt") -Append -Encoding UTF8

    # Also generate .nfo silently (separate call, nfo needs its own invocation)
    try {
        $nfoproc = Start-Process -FilePath "msinfo32.exe" -ArgumentList "/nfo `"$nfoFile`"" -PassThru -WindowStyle Hidden
        $nwaited = 0
        while (-not (Test-Path $nfoFile) -and $nwaited -lt 90) {
            Start-Sleep 2; $nwaited += 2
        }
        Start-Sleep 3
        if (-not $nfoproc.HasExited) { $nfoproc.Kill() }
        if (Test-Path $nfoFile) {
            Copy-Item $nfoFile (Join-Path $workDir "10a_msinfo32.nfo") -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    "msinfo32 report saved." | Out-File (Join-Path $workDir "10a_msinfo32.txt") -Append -Encoding UTF8
} else {
    "msinfo32 report not generated after 90s timeout." | Out-File (Join-Path $workDir "10a_msinfo32.txt") -Append -Encoding UTF8
}

Save-Output "10a2_memory_diagnostic.txt" {
    "=== Windows Memory Diagnostic Results (most recent run) ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'
        } -ErrorAction SilentlyContinue | Select-Object -First 5 |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, Message -Wrap
    } catch { "No Memory Diagnostic results found (run mdsched.exe to test RAM)." }
    ""
    "=== RAM Error Events (hardware memory errors) ===" | Out-String
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=(Get-Date).AddDays(-30)
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'WHEA' -and $_.Message -match 'memory|RAM|ECC|corrected' } |
        Sort-Object TimeCreated -Descending | Select-Object -First 20 |
        Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, Message -Wrap
    } catch {}
    ""
    "=== Current RAM config ===" | Out-String
    Get-WmiObject Win32_PhysicalMemory |
        Select-Object Tag,
            @{N='CapacityGB';E={[math]::Round($_.Capacity/1GB,1)}},
            @{N='SlotSpeed';E={"$($_.ConfiguredClockSpeed)MHz"}},
            BankLabel, DeviceLocator |
        Format-Table -AutoSize
}

Save-Output "10b_hotfixes_updates.txt" {
    "=== Installed Windows Updates / Hotfixes ===" | Out-String
    Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize HotFixID, Description, InstalledBy, InstalledOn
    ""
    "=== Pending Windows Updates (PSWindowsUpdate if available) ===" | Out-String
    if (Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue) {
        Get-WUList -ErrorAction SilentlyContinue | Format-Table -AutoSize
    } else { "PSWindowsUpdate module not installed — skipping." }
}

Save-Output "10b2_pending_reboot.txt" {
    "=== Pending Reboot Detection ===" | Out-String
    $rebootKeys = @{
        'CBS RebootPending'             = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'WindowsUpdate RebootRequired'  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        'PendingFileRenameOperations'   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        'ActiveComputerName mismatch'   = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName'
    }
    foreach ($label in $rebootKeys.Keys) {
        $path = $rebootKeys[$label]
        if ($label -eq 'PendingFileRenameOperations') {
            $smProps = Get-ItemProperty $path -ErrorAction SilentlyContinue
            $val = if ($smProps -and ($smProps.PSObject.Properties.Name -contains 'PendingFileRenameOperations')) { $smProps.PendingFileRenameOperations } else { $null }
            "$label : $(if ($val) { 'YES — pending file ops exist' } else { 'No' })"
        } elseif ($label -eq 'ActiveComputerName mismatch') {
            $active   = (Get-ItemProperty "$path\ActiveComputerName" -ErrorAction SilentlyContinue).ComputerName
            $pending  = (Get-ItemProperty "$path\ComputerName" -ErrorAction SilentlyContinue).ComputerName
            "ComputerName pending change: $(if ($active -ne $pending) { "YES ($active -> $pending)" } else { 'No' })"
        } else {
            "$label : $(if (Test-Path $path) { 'YES — reboot pending' } else { 'No' })"
        }
    }
}

Save-Output "10c_pagefile_virtual_memory.txt" {
    "=== Page File Config ===" | Out-String
    Get-WmiObject Win32_PageFileSetting | Format-Table -AutoSize Name, InitialSize, MaximumSize
    Get-WmiObject Win32_PageFileUsage  | Format-Table -AutoSize Name, AllocatedBaseSize, CurrentUsage, PeakUsage
}

Save-Output "10d_device_manager_full.txt" {
    "=== Full Device List with Status ===" | Out-String
    Get-WmiObject Win32_PnPEntity | Sort-Object Name |
        Select-Object Name, Status, DeviceID, ConfigManagerErrorCode |
        Format-Table -AutoSize
}

Save-Output "10e_bcd_boot_config.txt" {
    "=== Boot Configuration Data ===" | Out-String
    bcdedit /enum all 2>&1
    ""
    "=== Recent Boot Events ===" | Out-String
    Get-WinEvent -FilterHashtable @{
        LogName='System'; Id=@(12,13,41,1074,6006,6008); StartTime=(Get-Date).AddDays(-14)
    } -ErrorAction SilentlyContinue |
    Format-Table -AutoSize TimeCreated, Id, LevelDisplayName, Message -Wrap
}

Save-Output "10f2_environment_vars.txt" {
    "=== System Environment Variables ===" | Out-String
    [System.Environment]::GetEnvironmentVariables('Machine').GetEnumerator() |
        Sort-Object Name | Format-Table -AutoSize Name, Value -Wrap
    ""
    "=== User Environment Variables ===" | Out-String
    [System.Environment]::GetEnvironmentVariables('User').GetEnumerator() |
        Sort-Object Name | Format-Table -AutoSize Name, Value -Wrap
    ""
    "=== PATH entries (parsed) ===" | Out-String
    ($env:PATH -split ';') | Where-Object { $_ } | ForEach-Object {
        [PSCustomObject]@{
            Path    = $_
            Exists  = (Test-Path $_)
        }
    } | Format-Table -AutoSize
}

Save-Output "10f_autorun_registry.txt" {
    "=== Autorun Registry Keys ===" | Out-String
    $autoruns = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $autoruns) {
        try {
            if (-not (Test-Path $key)) { "--- $key --- (not found)"; continue }
            "--- $key ---"
            $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object { "$($_.Name) = $($_.Value)" }
            }
        } catch { "  (access denied or error: $_)" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# FINALIZE: Generate summary and zip
# ─────────────────────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "=== Generating summary report ==="

$summaryPath = Join-Path $workDir "00_SUMMARY.txt"
@"
========================================================
  DIAGNOSTIC COLLECTION SUMMARY
  Host       : $hostname
  Collected  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Admin Mode : $isAdmin
  Event Hours: $EventLogHours
========================================================

FILES IN THIS PACKAGE:
"@ | Out-File $summaryPath -Encoding UTF8

Get-ChildItem $workDir -Recurse |
    Where-Object { -not $_.PSIsContainer } |
    Sort-Object Name |
    Select-Object Name, @{N='SizeKB';E={[math]::Round($_.Length/1KB,1)}}, LastWriteTime |
    Format-Table -AutoSize | Out-File $summaryPath -Append -Encoding UTF8

@"

KEY THINGS TO CHECK:
  • 02a_events_system.txt   — Critical/Error events from System log
  • 02d_events_hardware.txt — WHEA hardware errors, disk/storage errors
  • 02e_reliability_history.txt — Crash/hang history
  • 03a_minidump_list.txt   — Minidumps (analyze with WinDbg/!analyze -v)
  • 03c_wer_reports.txt     — Windows Error Reporting crash details
  • 04b_drivers_problem.txt — Devices with driver errors
  • 04d_drivers_unsigned.txt— Unsigned/unverified drivers
  • 05c_disk_reliability_wmi.txt — SMART failure prediction
  • 06b_thermal_battery.txt — Thermal zone temps and battery wear
  • 10e_bcd_boot_config.txt — Event 41 (unexpected shutdown), 6008 (dirty shutdown)

NEXT STEPS:
  If minidumps exist: Load in WinDbg → !analyze -v
  If disk errors   : Run CrystalDiskInfo or smartctl -a /dev/pdX
  If driver issues : Run 'verifier /standard /all' (test VM only!)
  If BSOD persist  : Check 02d for WHEA errors → possible hardware fault

Collection log: collection_log.txt
"@ | Out-File $summaryPath -Append -Encoding UTF8

Write-Log "  Summary written to 00_SUMMARY.txt" "OK"

# ZIP the output
Write-Log "=== Creating ZIP archive ==="
$zipName = "DiagCollect_${hostname}_${stamp}.zip"
$zipPath = Join-Path $OutputDir $zipName

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($workDir, $zipPath, 'Optimal', $false)
    Write-Log "  ZIP saved to: $zipPath" "OK"
} catch {
    Write-Log "  ZIP failed via .NET — trying Compress-Archive" "WARN"
    Compress-Archive -Path "$workDir\*" -DestinationPath $zipPath -Force
    Write-Log "  ZIP saved to: $zipPath" "OK"
}

# Cleanup temp dir
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  DIAGNOSTICS COMPLETE                                        ║" -ForegroundColor Green
Write-Host "║  Archive: $zipName" -ForegroundColor Green
Write-Host "║  Location: $OutputDir" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
