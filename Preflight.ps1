#Requires -RunAsAdministrator
# Preflight module for OEM update flow and Win11 upgrade gating.
# - Detects manufacturer.
# - Removes system-installed DCU remnants on Dell to ensure a clean slate.
# - Validates Windows 11 readiness; exits 300 on failure.
# - If Dell: runs DCU updates (no auto-reboot).
# - On DCU success (exit code 0): schedules a one-time restart for "tonight" at a configurable time.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Configuration

# Configure the "tonight" restart time (local). If current time has already passed this,
# the task will be scheduled for the next calendar day at the same time.
# Example: 23 means 11:00 PM local time tonight.
$Global:RestartHourLocal = 23
$Global:RestartMinuteLocal = 0
$Global:OneTimeRestartTaskName = 'OneTime_Restart_After_DCU'

#endregion

#region Helpers: Manufacturer and Win11 Readiness

function Get-Manufacturer {
    <#
        .SYNOPSIS
        Returns the system manufacturer (e.g., "Dell Inc.", "Panasonic Corporation").
    #>
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        return $cs.Manufacturer
    } catch {
        Write-Warning "Unable to read system manufacturer: $($_.Exception.Message)"
        return $null
    }
}

function Test-Win11Readiness {
    <#
        .SYNOPSIS
        Performs a pragmatic Windows 11 readiness check.

        .DESCRIPTION
        Validates:
          - Physical RAM >= 4GB
          - Free space on system drive >= 64GB
          - Secure Boot enabled (UEFI)
          - TPM 2.0 present and enabled/activated

        .OUTPUTS
        PSCustomObject with booleans for each condition and an overall Ready flag.
    #>
    $ramOK = $false
    $diskOK = $false
    $secureBootOK = $false
    $tpmOK = $false

    # RAM check (>= 4GB)
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.TotalPhysicalMemory -ge 4GB) { $ramOK = $true }
    } catch {
        Write-Warning "RAM check failed: $($_.Exception.Message)"
    }

    # Disk free space on system drive (>= 64GB)
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $sysDriveLetter = $os.SystemDrive.TrimEnd(':')
        $sysDrive = Get-PSDrive -Name $sysDriveLetter
        if ($sysDrive.Free -ge 64GB) { $diskOK = $true }
    } catch {
        Write-Warning "Disk space check failed: $($_.Exception.Message)"
    }

    # Secure Boot (only supported on UEFI; will throw on legacy/unsupported)
    try {
        if (Confirm-SecureBootUEFI) { $secureBootOK = $true }
    } catch {
        $secureBootOK = $false
    }

    # TPM 2.0 present and ready
    try {
        $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm -ErrorAction Stop
        if ($tpm -and ($tpm.SpecVersion -match '2\.0') -and $tpm.IsEnabled_Initial -and $tpm.IsActivated_Initial) {
            $tpmOK = $true
        }
    } catch {
        $tpmOK = $false
    }

    [pscustomobject]@{
        RamOK        = $ramOK
        DiskOK       = $diskOK
        SecureBootOK = $secureBootOK
        TpmOK        = $tpmOK
        Ready        = ($ramOK -and $diskOK -and $secureBootOK -and $tpmOK)
    }
}

#endregion

#region DCU Removal (system-installed variants only; no UWP/Appx; no Integration Suite)

function Stop-DellServicesAndProcesses {
    <#
        .SYNOPSIS
        Stops known DCU-related services and processes to prevent file locks during uninstall.
    #>
    $services = @(
        'DellClientManagementService',
        'DellUpdateService',
        'DellUpdate'
    )

    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            try {
                if ($s.Status -ne 'Stopped') {
                    Stop-Service -Name $svc -Force -ErrorAction Stop
                    Start-Sleep -Seconds 2
                }
            } catch {
                Write-Warning "Failed to stop service '$svc': $($_.Exception.Message)"
            }
        }
    }

    $procs = @('dcu-cli','dcu','DellCommandUpdate','DellUpdate','DellClientManagementService')
    foreach ($p in $procs) {
        Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
            } catch {
                # Non-fatal
            }
        }
    }
}

function Uninstall-DellCommandUpdate {
    <#
        .SYNOPSIS
        Removes system-installed variants of Dell Command | Update (DCU).

        .DESCRIPTION
        Searches both native and Wow6432 uninstall registry hives for entries whose DisplayName
        matches DCU, then attempts a silent uninstall (MSI or EXE).
        Does not remove Dell Command | Integration Suite and does not attempt any Appx/UWP removals.

        .OUTPUTS
        [bool] True if at least one DCU instance was removed; otherwise False.
    #>

    $removed = $false

    Stop-DellServicesAndProcesses

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $displayNamePatterns = @(
        'Dell Command\s*\|\s*Update',  # "Dell Command | Update"
        '^Dell Update$'                # Legacy "Dell Update"
    )

    foreach ($root in $uninstallRoots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in Get-ChildItem $root) {
            $props = Get-ItemProperty $key.PsPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $dn = $props.DisplayName
            if ([string]::IsNullOrWhiteSpace($dn)) { continue }

            $isMatch = $displayNamePatterns | Where-Object { $dn -match $_ }
            if (-not $isMatch) { continue }

            try {
                $uninstallString = $props.UninstallString
                $productCode = if ($key.PSChildName -match '^\{[0-9A-F\-]+\}$') { $key.PSChildName } else { $null }

                if ($uninstallString) {
                    if ($uninstallString -match 'msiexec\.exe.*?/x\s*(\{[0-9A-F\-]+\})') {
                        $code = $Matches[1]
                        Write-Host "Uninstalling MSI DCU $dn ($code) silently..."
                        Start-Process "msiexec.exe" -ArgumentList "/x $code /qn /norestart" -Wait -NoNewWindow
                        $removed = $true
                        continue
                    }

                    if ($uninstallString -match 'msiexec\.exe' -and $productCode) {
                        Write-Host "Uninstalling MSI DCU $dn by product code silently..."
                        Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                        $removed = $true
                        continue
                    }

                    # EXE uninstaller: try common silent switches
                    $exe = $uninstallString
                    $args = ''
                    if ($uninstallString -match '^(?<exe>".+?\.exe"|.+?\.exe)\s+(?<args>.+)$') {
                        $exe  = $Matches['exe'].Trim('"')
                        $args = $Matches['args']
                    }

                    $candidateArgs = @(
                        "$args /quiet /norestart",
                        "$args /s /v`"/qn /norestart`"",
                        "$args /S",
                        "/quiet /norestart"
                    ) | Select-Object -Unique

                    $succeeded = $false
                    foreach ($a in $candidateArgs) {
                        try {
                            Start-Process $exe -ArgumentList $a -Wait -NoNewWindow -ErrorAction Stop
                            $succeeded = $true
                            break
                        } catch {
                            # try next
                        }
                    }

                    if (-not $succeeded -and $productCode) {
                        Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                        $succeeded = $true
                    }

                    if ($succeeded) { $removed = $true }
                }
                elseif ($productCode) {
                    Write-Host "Uninstalling MSI DCU by product code $productCode..."
                    Start-Process "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -NoNewWindow
                    $removed = $true
                }
            } catch {
                Write-Warning "Uninstall attempt failed for '$dn': $($_.Exception.Message)"
            }
        }
    }

    Stop-DellServicesAndProcesses
    return $removed
}

#endregion

#region DCU Execution (Dell only) and One-Time Restart Scheduling

function Find-DcuCliPath {
    <#
        .SYNOPSIS
        Locates dcu-cli.exe in common install directories.

        .OUTPUTS
        Full path to dcu-cli.exe if found; otherwise $null.
    #>
    $candidates = @(
        "$Env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
        "$Env:ProgramFiles(x86)\Dell\CommandUpdate\dcu-cli.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Invoke-DellCommandUpdate {
    <#
        .SYNOPSIS
        Runs Dell Command | Update in silent mode without reboot.

        .DESCRIPTION
        Uses dcu-cli.exe to apply updates. Reboot is disabled; we handle restart
        via a scheduled task after confirming a successful exit code.

        .OUTPUTS
        [int] Process exit code from DCU (0 indicates success).
    #>
    $cli = Find-DcuCliPath
    if (-not $cli) {
        Write-Warning "dcu-cli.exe not found. Ensure your managed DCU is installed before invoking updates."
        return -1
    }

    # Recommended: explicitly disable reboot and run silent.
    # You may add additional switches (catalog, suspend BitLocker) if required by your environment.
    $args = '/applyUpdates -silent -reboot=disable'
    Write-Host "Starting DCU updates via: `"$cli`" $args"
    $proc = Start-Process -FilePath $cli -ArgumentList $args -PassThru -Wait -NoNewWindow
    $exitCode = $proc.ExitCode
    Write-Host "DCU exit code: $exitCode"
    return $exitCode
}

function Get-TonightDateTime {
    <#
        .SYNOPSIS
        Computes the DateTime for "tonight" at configured hour/minute (local time).
        If now has already passed that time, returns the same time on the next day.
    #>
    $target = [datetime]::Today.AddHours($Global:RestartHourLocal).AddMinutes($Global:RestartMinuteLocal)
    if ((Get-Date) -ge $target) {
        $target = $target.AddDays(1)
    }
    return $target
}

function Register-OneTimeRestartTask {
    <#
        .SYNOPSIS
        Creates or replaces a one-time scheduled task to restart the device "tonight".

        .DESCRIPTION
        - Runs as SYSTEM with highest privileges.
        - Executes: shutdown.exe /r /f /t 0
        - Trigger time computed by Get-TonightDateTime().

        .OUTPUTS
        None. Throws on failure.
    #>
    $runAt = Get-TonightDateTime
    Write-Host "Registering one-time restart task '$($Global:OneTimeRestartTaskName)' for $runAt"

    # Remove any prior instance of the same task name to avoid duplicate triggers.
    try {
        Unregister-ScheduledTask -TaskName $Global:OneTimeRestartTaskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        # Non-fatal if not present
    }

    $action     = New-ScheduledTaskAction  -Execute 'shutdown.exe' -Argument '/r /f /t 0'
    $trigger    = New-ScheduledTaskTrigger -Once -At $runAt
    $principal  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings   = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $Global:OneTimeRestartTaskName `
                           -Action $action `
                           -Trigger $trigger `
                           -Principal $principal `
                           -Settings $settings `
                           -Force | Out-Null

    Write-Host "One-time restart task created successfully."
}

#endregion

#region Entry Point

function Invoke-Preflight {
    <#
        .SYNOPSIS
        Orchestrates manufacturer detection, DCU removal on Dell, Win11 readiness, Dell updates, and one-time restart scheduling.

        .DESCRIPTION
        1) Detect manufacturer.
        2) If Dell: remove any pre-existing system-installed DCU to avoid collisions.
        3) Validate Windows 11 readiness; exit 300 on failure.
        4) If Dell: run DCU updates silently with reboot disabled.
        5) If DCU returned exit code 0, schedule a one-time restart for tonight.
    #>
    $manufacturer = Get-Manufacturer
    Write-Host "Manufacturer detected: $manufacturer"

    if ($manufacturer -match 'Dell') {
        Write-Host "Dell hardware detected. Ensuring no pre-existing DCU remains..."
        [void](Uninstall-DellCommandUpdate)
    } else {
        Write-Host "Non-Dell hardware detected. Skipping DCU removal and DCU updates."
    }

    $readiness = Test-Win11Readiness
    Write-Host ("Windows 11 readiness result: {0}" -f ($readiness | ConvertTo-Json -Compress))
    if (-not $readiness.Ready) {
        Write-Warning "Device does not meet Windows 11 requirements. Exiting with code 300."
        exit 300
    }

    if ($manufacturer -match 'Dell') {
        # At this point, your packaging should have installed your managed DCU.
        $dcuExit = Invoke-DellCommandUpdate

        if ($dcuExit -eq 0) {
            # Only schedule restart if DCU completed successfully.
            Register-OneTimeRestartTask
        } else {
            Write-Warning "DCU did not report success (exit code $dcuExit). No restart task will be scheduled."
        }
    }
}

#endregion

# Invoke when executed directly. If dot-sourcing, comment out and call Invoke-Preflight from your main script.
Invoke-Preflight
