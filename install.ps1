function Test-Administrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}
function Get-OSBitness {
    return (Get-WmiObject Win32_OperatingSystem).OSArchitecture.substring(0, 2)
}
function Test-Installed {
    param (
        [Parameter(Mandatory)]
        [string]$BinaryName
    )

    if (Get-Command $BinaryName -ErrorAction SilentlyContinue) {
        return $true
    } else {
        return $false
    }
}
function Install-Git {
    $git_installer = "$env:TEMP\Git-Installer.exe"
    $bitness = Get-OSBitness
    Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.51.0.windows.1/Git-2.51.0-$bitness-bit.exe" -OutFile $git_installer
    Start-Process -FilePath $git_installer -ArgumentList "/VERYSILENT /NORESTART" -Wait
    Remove-Item -Force $git_installer
}
function Start-Installer () {
    # Navigate to the script's directory
    Set-Location $PSScriptRoot

    $repo = "https://github.com/svobodacenter/xray-client-win"
    
    # Install git
    if (-not (Test-Installed "git")) {
        Install-Git
    }

    # Clone the repository
    try {
        git clone $repo
    } catch {
        Write-Error "[x] Failed to download and extract the client"
        exit 1
    }

    # Copy config into client's directory
    if (-not (Test-Path "config.json")) {
        Write-Host "[!] There is no config.json in the current directory"
    } else {
        Copy-Item config.json xray-client-win\config.json
    }

    # Navigate to the client's directory
    Set-Location xray-client-win

    if (-not (Test-Path "config.json")) {
        Write-Host "[?] Put config.json in the current directory and run '.\run.ps1 -Install'"
        exit
    }

    .\run.ps1 -Install
}

if (Test-Administrator) {
    Start-Installer
}
else {
    Write-Host "[!] This script requires administrator privileges."
    Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
}