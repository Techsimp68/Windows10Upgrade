# Preflight Script for OEM Updates and Windows 11 Upgrade Readiness

## Overview
This PowerShell script is designed for use in enterprise environments where devices are managed via Microsoft Intune (or a hybrid SCCM/Intune configuration).  
It performs pre-update checks, removes unmanaged OEM utilities that could conflict with corporate deployments, runs OEM firmware/software updates, and optionally schedules a system restart.

The script has been tailored for Dell and Panasonic endpoints, with special handling for Dell Command | Update (DCU).

---

## Key Features

1. **Manufacturer Detection**
   - Identifies the device manufacturer via WMI (`Win32_ComputerSystem`).
   - Allows conditional logic for Dell and Panasonic hardware.

2. **Windows 11 Readiness Check**
   - Validates key requirements:
     - RAM ≥ 4GB
     - Free disk space on system drive ≥ 64GB
     - Secure Boot enabled
     - TPM 2.0 present and active
   - Exits with code **300** if requirements are not met.

3. **Dell Command | Update (DCU) Removal (Dell only)**
   - Detects and uninstalls **system-installed** DCU instances (e.g., from SCCM) to prevent version conflicts.
   - Targets MSI/EXE-based installs from standard uninstall registry hives.
   - Does **not** remove:
     - Appx/UWP packages
     - Dell Command | Integration Suite

4. **Run Managed DCU Updates (Dell only)**
   - Executes the managed DCU (`dcu-cli.exe`) in silent mode without reboot (`/applyUpdates -silent -reboot=disable`).
   - Logs the exit code for reporting and decision-making.

5. **One-Time Restart Scheduling (Dell only, on success)**
   - If DCU completes successfully (`exit code 0`), schedules a **one-time restart task** for the current day at a configurable time (default: **23:00 local**).
   - Runs the restart as SYSTEM with highest privileges.

---

## Script Flow

1. **Manufacturer detection**  
   `Dell` → Remove unmanaged DCU → Proceed to updates.  
   Other manufacturers → Skip DCU removal and DCU update execution.

2. **Windows 11 readiness check**  
   Fails fast with exit code 300 if requirements are not met.

3. **If Dell hardware**:
   - Run managed DCU update command.
   - If updates succeed, create scheduled restart task for “tonight.”

---

## Configuration

At the top of the script:

```powershell
$Global:RestartHourLocal = 23   # Restart hour (24-hour format)
$Global:RestartMinuteLocal = 0 # Restart minute
$Global:OneTimeRestartTaskName = 'OneTime_Restart_After_DCU'

