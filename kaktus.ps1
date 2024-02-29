param (
    [string]$lgpoToolExecutable = "LGPO.exe",
    [string]$scriptDirectory = ".\",
    [string]$logFile = ".\hardening_log.txt",
    [switch]$confirmChanges = $true,
    [string]$emailFrom = "script@example.com",
    [string]$emailTo = "admin@example.com",
    [string]$smtpServer = "smtp.example.com"
)

# Function to detect Windows version
function Get-WindowsVersion {
    $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
    switch -Regex ($osVersion) {
        '^10\.0\..*' { return "Windows 10" }
        '^10\.0\.(\d+)\..*' {
            if ([int]$matches[1] -ge 22000) {
                return "Windows 11"
            }
            else {
                return "Windows 10"
            }
        }
        '^6\.3\..*' { return "Windows 8.1 / Server 2012 R2" }
        '^6\.2\..*' { return "Windows 8 / Server 2012" }
        '^6\.1\..*' { return "Windows 7 / Server 2008 R2" }
        '^6\.0\..*' { return "Windows Vista / Server 2008" }
        '^5\.1\..*' { return "Windows XP" }
        default { return "Unknown" }
    }
}

# Function to confirm changes
function Confirm-Changes {
    if ($confirmChanges) {
        $confirmation = Read-Host "Do you want to apply hardening configurations? (Y/N)"
        if ($confirmation -ne "Y" -and $confirmation -ne "y") {
            Write-Host "Aborting script."
            exit 0
        }
    }
}

# Function to create backups
function Backup-Settings {
    param (
        [string]$lgpoPath,
        [string]$regPath
    )
    # Create backup folder if it doesn't exist
    $backupFolder = Join-Path $scriptDirectory "Backup"
    if (-not (Test-Path $backupFolder -PathType Container)) {
        New-Item -ItemType Directory -Path $backupFolder | Out-Null
    }
    # Backup LGPO settings
    Copy-Item -Path "$($lgpoPath)\lgpo.zip" -Destination $backupFolder -Force
    # Backup registry changes
    Copy-Item -Path "$($regPath)\registry.reg" -Destination $backupFolder -Force
    Write-Host "Backup created successfully in $backupFolder."
}

# Function to restore backups
function Restore-Backups {
    param (
        [string]$lgpoPath,
        [string]$regPath
    )
    Write-Host "Rolling back changes..."
    Write-LogMessage "Rolling back changes..."
    # Revert LGPO settings
    Copy-Item -Path "$($lgpoPath)\lgpo.zip" -Destination $lgpoPath -Force
    # Revert registry changes
    Copy-Item -Path "$($regPath)\registry.reg" -Destination $regPath -Force
    Write-Host "Restored from backup."
}

# Function to apply LGPO settings
function Set-LGPOSettings {
    param (
        [string]$lgpoPath
    )
    # Execute LGPO tool
    $lgpoExecutable = Join-Path $lgpoPath $lgpoToolExecutable
    Start-Process -FilePath $lgpoExecutable -ArgumentList "/g $($lgpoPath)\lgpo.zip" -Wait
    # Check for errors
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to apply LGPO settings. Exit code: $LASTEXITCODE"
        Write-LogMessage "Error: Failed to apply LGPO settings. Exit code: $LASTEXITCODE"
        exit 1
    }
}

# Function to write log message
function Write-LogMessage {
    param (
        [string]$message
    )
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

# Function to send email notification
function Send-EmailNotification {
    param (
        [string]$body,
        [string]$subject
    )
    $emailParams = @{
        SmtpServer = $smtpServer
        From = $emailFrom
        To = $emailTo
        Subject = $subject
        Body = $body
    }
    Send-MailMessage @emailParams
}

# Function to undo changes
function Undo-Changes {
    param (
        [string]$lgpoPath,
        [string]$regPath
    )
    Write-Host "Rolling back changes..."
    Write-LogMessage "Rolling back changes..."
    Restore-Backups -lgpoPath $lgpoPath -regPath $regPath
    Write-LogMessage "Changes rolled back successfully."
}

# Main script

try {
    # Log start time
    Write-LogMessage "Script started."

    # Confirm changes
    Confirm-Changes

    # Get Windows version
    $windowsVersion = Get-WindowsVersion
    Write-LogMessage "Detected Windows version: $windowsVersion."

    # Determine paths based on Windows version
    $lgpoPath = Join-Path $scriptDirectory $windowsVersion "LGPO"
    $regPath = Join-Path $scriptDirectory $windowsVersion "Reg"

    # Validate paths
    if (-not (Test-Path $lgpoPath -PathType Container) -or -not (Test-Path $regPath -PathType Container)) {
        Write-Host "Error: LGPO or registry folders not found for $windowsVersion."
        Write-LogMessage "Error: LGPO or registry folders not found for $windowsVersion."
        exit 1
    }

    # Backup settings
    Backup-Settings -lgpoPath $lgpoPath -regPath $regPath

    # Apply LGPO settings
    Set-LGPOSettings -lgpoPath $lgpoPath
    Write-LogMessage "LGPO settings applied successfully."

    # Import registry changes
    Import-RegistryChanges -regPath $regPath
    Write-LogMessage "Registry changes imported successfully."

    # Log success
    Write-LogMessage "Hardenings applied successfully for $windowsVersion."

    # Log end time
    Write-LogMessage "Script completed."
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error occurred: $errorMessage"
    Write-LogMessage "Error occurred: $errorMessage"

    # Rollback changes
    Undo-Changes -lgpoPath $lgpoPath -regPath $regPath

    # Send email notification
    $emailBody = "An error occurred during script execution:`n$errorMessage`n`nChanges have been rolled back."
    $emailSubject = "Error: Script Execution Report"
    Send-EmailNotification -body $emailBody -subject $emailSubject
}

# End of script
