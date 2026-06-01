# DiagCollect - Windows Diagnostics Toolkit

A PowerShell diagnostics collector for Windows 10/11 that gathers crash dumps, driver errors, hardware health, performance data, and event logs into a single timestamped ZIP - ready to hand off for analysis.

---

## Quick Start

1. Extract the ZIP to any folder (e.g. your Desktop)
2. Double-click **`Run-Diagnostics.bat`**
3. Accept the UAC prompt (admin rights needed for full collection)
4. Wait 2-5 minutes for collection to complete
5. The output ZIP appears on your Desktop as `DiagCollect_<HOSTNAME>_<TIMESTAMP>.zip`

---

## What It Collects

| Category | Details |
|---|---|
| **System Info** | CPU, RAM, GPU, BIOS version, motherboard, uptime |
| **Event Logs** | Critical/Error events from System & Application logs, WHEA hardware errors, disk/storport/NTFS errors, Kernel-Power events (Event 41 = dirty shutdown) |
| **GPU / Display** | TDR crash events (`nvlddmkm`, `atikmpag`, `dxgkrnl`), display driver timeouts |
| **Crash Data** | Up to 20 most recent minidumps (`.dmp`), WER fault reports, app crash (1000) / hang (1002) / fault bucket (1001) events, crash dump config from registry |
| **Driver Info** | All installed drivers with version & date, devices with error codes (Code 10, Code 28, etc.), unsigned driver list, Driver Verifier status |
| **Storage Health** | Physical disk `HealthStatus`/`OperationalStatus`, WMI SMART pass/fail prediction, chkdsk results (Wininit event log), dirty bit status per volume, Storage Spaces status |
| **Performance** | CPU & RAM snapshot, top 20 processes by CPU and by memory, page file usage |
| **Thermal & Power** | Thermal zone temps (°C), battery wear %, battery report (HTML), sleep study (HTML), power scheme config, wake timers |
| **System Integrity** | CBS.log tail (SFC), DISM log tail, pending reboot detection (CBS / WU / PendingFileRename) |
| **Memory** | Windows Memory Diagnostic results, WHEA corrected memory errors, RAM slot/speed summary |
| **Network** | Adapters, IP config, active TCP connections with owning process, listening ports, WLAN details, USB hub/port errors |
| **Software** | Installed programs, startup items, non-Microsoft scheduled tasks, services in unexpected stopped state |
| **Advanced** | `msinfo32` full report (`.txt` + `.nfo`), installed hotfixes, BCD boot config, environment variables, PATH validity check, autorun registry keys |

---

## Optional: Full SMART Disk Data

By default only WMI-based SMART pass/fail prediction is collected. For full per-attribute data (reallocated sectors, pending sectors, uncorrectable errors, spin retry count, etc.):

1. Download **smartmontools**: https://www.smartmontools.org/wiki/Download
2. Place `smartctl.exe` in the `tools\` folder next to the script
3. Re-run - full SMART output will be saved to `05d_smart_full.txt`

---

## Advanced Usage

Run directly from an elevated PowerShell prompt with optional parameters:

```powershell
# Collect 7 days of event logs instead of the default 72 hours
.\Collect-Diagnostics.ps1 -EventLogHours 168

# Skip minidump copying (faster, smaller ZIP)
.\Collect-Diagnostics.ps1 -SkipMinidumps

# Skip SMART checks
.\Collect-Diagnostics.ps1 -SkipSMART

# Omit network information
.\Collect-Diagnostics.ps1 -SkipNetworkInfo

# Write the output ZIP to a custom path
.\Collect-Diagnostics.ps1 -OutputDir C:\Temp
```

---

## Analyzing Minidumps

If minidumps are present in the ZIP, open them with **WinDbg** (available from the Microsoft Store or Windows SDK):

```
.symfix
.reload
!analyze -v
```

The `MODULE_NAME` and `IMAGE_NAME` fields in the output identify the offending driver or component.

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges (non-admin run collects partial data)
