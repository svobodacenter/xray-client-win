param (
    [string]$Config = "config.json",
    [string]$Blacklist = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
    [string]$BackupDNS = $null,
    [string]$Log = $null,
    [string]$WindowStyle = "Hidden",
    [switch]$Install = $false,
    [switch]$Uninstall = $false,
    [switch]$Start = $false,
    [switch]$Stop = $false,
    [switch]$Service = $false,
    [switch]$Nokillswitch = $false,
    [switch]$KillswitchOff = $false,
    [switch]$KillswitchOn = $false,
    [switch]$Torify = $false,
    [switch]$NoFilter = $false
)

function Test-Windows {
    return ($env:OS -match 'Windows')
}
function Test-Administrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}
function Get-OSBitness {
    return (Get-WmiObject Win32_OperatingSystem).OSArchitecture.substring(0, 2)
}
function Get-ProcessorArchitecture {
    return $env:PROCESSOR_ARCHITECTURE.ToLower()
}
function curl {
    param (
        [string]$Url
    )
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -ErrorAction Stop
        $response.Content | Out-Host
    } catch {
        Write-Error "[-] Unable to connect to the internet or resolve the URL."
        exit 1
    }
}
function Test-FileWritable {
    param ([string]$FilePath)
    try {
        $file = [System.IO.File]::Open($FilePath, "Append", "Write")
        $file.Close()
        return $true
    } catch {
        return $false
    }
}

function Invoke-FileDownload {
    param (
        [string]$Url,
        [string]$OutputPath
    )
    if (-not $OutputPath) {
        $OutputPath = (Split-Path $Url -Leaf)
    }
    try {
        if (-not (Test-FileWritable $OutputPath)) {
            Write-Error "[-] Unable to download $Url, $OutputPath is not writable"
            exit 1
        }
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -ErrorAction Stop
    } catch {
        Write-Error "[-] Unable to connect to the internet or resolve the URL: $($_.Exception)"
        exit 1
    }
}
function Add-ToPath {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    $trimmed_path = $env:PATH.TrimEnd(';')
    if ($trimmed_path -like "*$Path*") {
        Write-Host "[!] The path '$Path' is already in the PATH."
    } else {
        $new_path = $trimmed_path + ";" + $Path
        [Environment]::SetEnvironmentVariable("PATH", $new_path, [EnvironmentVariableTarget]::Machine)
        $env:PATH = $new_path
    }
}
function Remove-FromPath {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    if ($env:PATH -notlike "*$Path*") {
        Write-Host "[!] The path '$Path' is not in the PATH."
    } else {
        $current_path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
        $new_path = ($current_path -split ';' | Where-Object { $_ -ne $Path }) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $new_path, [EnvironmentVariableTarget]::Machine)
        $env:PATH = $new_path
    }
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
function Show-Help {
    $help_text = @"
Windows CLI client for DNSCrypt + tun2socks + Xray-core by https://svoboda.center
Usage: .\svoboda-vpn-windows.ps1 [OPTIONS]

Options:
-Config PATH                Specify the configuration file (default: ./config.json)
-Install                    Install dependencies, set up auto-start on boot, start, then exit this script."
-Uninstall                  Uninstall, then exit."
-Blacklist URL              Url to DNSCrypt-compatible DNS blacklist. Default is Hagezi Multi PRO++ - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt."
-BackupDNS IP               Optional backup DNS server in case DNSCrypt servers are down or DNSCrypt-proxy is failing. QUERIES SENT TO THE BACKUP SERVER WILL NOT BE ENCRYPTED OR AUTHENTICATED."
-Nofilter                   Turn off DNS blacklist for blocking ads & tracking
-Nokillswitch               Don't turn on killswitch. Killswitch is turned on by default."
-KillswitchOff              Turn off killswitch and exit."
-KillswitchOn               Turn on killswitch and exit."
-Torify                     Route traffic through VPN and then Tor. Assumes VPN server runs Tor on port 9050."
-Log PATH                   Specify the log file (default: output log to console).
-WindowStyle Hidden|Normal  Show xray and tun2socks output in separate windows. Default is Hidden.
-Help                       Show this help message.
"@
    Write-Host $help_text
}

if (-not (Test-Windows)) {
   Write-Error "[x] This script is only for Windows."
   exit 1
}

if ($PSVersionTable.PSVersion.Major -ne 5) {
    Write-Host "[x] PowerShell 5 is required"
}

if (-not (Test-Administrator)) {
    Write-Host "[!] This script requires administrator privileges."
    Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
    exit 1
}

if ($Config -eq "config.json") {
    $Config = Join-Path $PSScriptRoot $Config
}

if (-not (Test-Path $Config)) {
    Write-Error "[x] Config file not found: $Config"
    exit 1
}

if ($Log) {
    if (-not (Test-FileWritable $Log)) {
        Write-Error "[!] Can't log to $log, check file permissions and if the file is being used by another process"
    } else {
        Start-Transcript -Path $Log
    }
}

$bitness = Get-OSBitness
$arch = Get-ProcessorArchitecture
$tmp_dir = Join-Path $env:TEMP "svoboda-vpn"
$dnscrypt_proxy_download_path = (Join-Path $env:ProgramFiles "dnscrypt-proxy")
$dnscrypt_proxy_final_path = Join-Path $dnscrypt_proxy_download_path "win$bitness"
$dnscrypt_proxy_conf = Join-Path $dnscrypt_proxy_final_path "dnscrypt-proxy.toml"
$dns_blacklist_url = $Blacklist
$dns_blacklist_path = Join-Path $dnscrypt_proxy_final_path "blacklist.txt"
$xray_path = Join-Path $env:ProgramFiles "xray-core"
$xray_binary = Join-Path $xray_path "xray.exe"
$xray_config = Join-Path $xray_path "config.json"
$tun2socks_path = Join-Path $env:ProgramFiles "tun2socks"
$tun2socks_binary = Join-Path $tun2socks_path "tun2socks.exe"

$TUN_NAME = "wintun"
$TASK_NAME = "svoboda.center VPN"
$TASK_DIR = Join-Path $env:ProgramFiles "svoboda.center VPN"
$TASK_LOG = Join-Path $TASK_DIR "app.log"
$TASK_EVENT_NAME = "Exit event for svoboda.center VPN task"
$SCRIPT_PATH = $PSCommandPath
$SCRIPT_DIR = Split-Path -Path $SCRIPT_PATH -Parent
$SCRIPT_ARGS = $args

$script:XRAY_PID = $null 
$script:TUN2SOCKS_PID = $null
$script:default_interface = $null
$script:default_interface_ip = $null
$script:gateway_ip = $null
$script:xray_address = $null
$script:xray_ip = $null
$script:dnscrypt_servers = New-Object System.Collections.Generic.List[System.String]

function Test-FileStale {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [int]$Days
    )

    $last_modified = (Get-ItemProperty -Path $FilePath).LastWriteTime
    $days_since_last_modified = (Get-Date).Subtract($last_modified).Days
    return ($days_since_last_modified -gt $Days)
}

function Receive-DNSBlacklist {
    if (-not (Test-Path -Path $dns_blacklist_path)) {
        Write-Host "[~] DNS Blacklist file does not exist, downloading..."
        Invoke-FileDownload -Url $dns_blacklist_url -OutputPath $dns_blacklist_path 
        Write-Host "[+] DNS Blacklist downloaded"
    }
    elseif (Test-FileStale -FilePath $dns_blacklist_path -Days 7) {
        Write-Host "[~] DNS Blacklist file is stale, downloading..."
        Invoke-FileDownload -Url $dns_blacklist_url -OutputPath $dns_blacklist_path 
        Write-Host "[+] DNS Blacklist downloaded"
    } else {
        Write-Host "[+] DNS blacklist is up to date"
    }
}

function Add-DNSBlacklist {
    Write-Host  "[~] Adding DNS blacklist..."

    "[blocked_names]`nblocked_names_file = 'blacklist.txt'" | Out-File -Append -FilePath $dnscrypt_proxy_conf -Encoding UTF8

    Restart-Service dnscrypt-proxy 

    Write-Host "[+] DNS Blacklist added"
}

function Remove-DNSBlacklist {
    Write-Host "[~] Removing DNS blacklist..."

    (Get-Content $dnscrypt_proxy_conf) -replace "^\[blocked_names\]", '' -join "`n" | Set-Content -Path $dnscrypt_proxy_conf -Encoding UTF8
    (Get-Content $dnscrypt_proxy_conf) -replace "^blocked_names_file = 'blacklist.txt'", '' -join "`n" | Set-Content -Path $dnscrypt_proxy_conf -Encoding UTF8

    Restart-Service dnscrypt-proxy 

    Write-Host "[+] DNS Blacklist removed"
}

function Test-DNSBlacklistEnabled {
    if ((Select-String -Pattern '^\[blocked_names\]' -Path $dnscrypt_proxy_conf) -and 
        (Select-String -Pattern "blocked_names_file = 'blacklist.txt'" -Path $dnscrypt_proxy_conf)) {
        return $true
    } else {
        return $false
    }
}

function Install-DNSCryptProxy {
    Write-Host "[~] Installing dnscrypt-proxy..."

    try {
        $dnscrypt_proxy_version = (curl https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir dnscrypt-proxy.zip)
        Invoke-FileDownload -Url "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/$dnscrypt_proxy_version/dnscrypt-proxy-win$bitness-$dnscrypt_proxy_version.zip" -OutputPath $zip
        $existing_service = Get-Service "dnscrypt-proxy" -ErrorAction SilentlyContinue
        if ($existing_service) {
            if ($existing_service.Status -eq "Running") {
                Stop-Service "dnscrypt-proxy" -ErrorAction SilentlyContinue
            }
        }
        Expand-Archive -Path $zip -DestinationPath $dnscrypt_proxy_download_path -Force
        Remove-item $zip

        Copy-Item config/dnscrypt-proxy.toml $dnscrypt_proxy_conf

        $dnscrypt_proxy_exe = Join-Path $dnscrypt_proxy_final_path "dnscrypt-proxy.exe"
        Add-ToPath $dnscrypt_proxy_final_path

        & $dnscrypt_proxy_exe -service install 2> $null
        & $dnscrypt_proxy_exe -service start 2> $null

        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\MICROSOFT\Windows\NetworkConnectivityStatusIndicator" /v UseGlobalDNS /t REG_DWORD /d 1 /f | Out-Null

        Write-Host "[+] dnscrypt-proxy installed"
    } catch {
        Write-Error "[-] Failed to install dnscrypt-proxy: $($_.Exception)"
        exit 1
    }
}

function Get-DefaultInterfaceAlias {
    return Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object -Property RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias
}
function Get-InterfaceIP {
    param (
        [string]$InterfaceAlias
    )
    return Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
}
function Get-GatewayIP {
    param (
        [string]$InterfaceAlias
    )
    return Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty NextHop
}
function Set-SystemDNS {
    Write-Host "[~] Setting system DNS..."

    if ($BackupDNS) {
        Set-DnsClientServerAddress -InterfaceAlias $script:default_interface -ServerAddresses ("127.0.0.1", $BackupDNS)
    } else {
        Set-DnsClientServerAddress -InterfaceAlias $script:default_interface -ServerAddresses ("127.0.0.1")
    }

    Write-Host "[+] Set system DNS"
}

function Install-Xray {
    try {
        Write-Host "[~] Downloading xray-core..."
        $xray_version = (curl https://api.github.com/repos/xtls/Xray-core/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir xray.zip)
        Invoke-FileDownload -Url "https://github.com/xtls/Xray-core/releases/download/$xray_version/Xray-windows-$bitness.zip" -OutputPath $zip
        Expand-Archive -Path $zip -DestinationPath $xray_path
        Remove-Item $zip

        Add-ToPath -Path $xray_path

        $user = "$env:USERNAME"

        Write-Host "[+] xray-core installed"
    } catch {
        Write-Error "[-] Failed to install xray-core: $($_.Exception)"
        exit 1
    }
}

function Receive-GeoIP() {
    $geoip_url = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
    $geoip_file = Join-Path $xray_path "geoip.dat"
    if (-not (Test-Path -Path $geoip_file) -or (Test-FileStale -FilePath $geoip_file -Days 7)) {
        Write-Host "[~] Downloading geoip.dat..."
        Invoke-FileDownload -Url $geoip_url -OutputPath $geoip_file
        Write-Host "[+] Downloaded geoip.dat..."
    }
}
function Receive-Geosite() {
    $geosite_url = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
    $geosite_file = Join-Path $xray_path "geosite.dat"

    if (-not (Test-Path -Path $geosite_file) -or (Test-FileStale -FilePath $geosite_file -Days 7)) {
        Write-Host "[~] Downloading geosite.dat..."
        Invoke-FileDownload -Url $geosite_url -OutputPath $geosite_file
        Write-Host "[+] Downloaded geosite.dat..."
    }
}

function Install-Tun2socks {
    Write-Host "[~] Downloading tun2socks..."

    try {
        $tun2socks_version = (curl https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir tun2socks.zip)
        Invoke-FileDownload -Url "https://github.com/xjasonlyu/tun2socks/releases/download/$tun2socks_version/tun2socks-windows-$arch.zip" -OutputPath $zip
        Expand-Archive -Path $zip -DestinationPath $tun2socks_path
        Remove-Item $zip
        Move-Item (Join-Path $tun2socks_path tun2socks-*) $tun2socks_binary

        Write-Host "[~] Downloading wintun..."
        $zip_filename = "wintun-0.14.1.zip"
        Invoke-FileDownload "https://www.wintun.net/builds/$zip_filename" -O $zip_filename
        Expand-Archive -Path $zip_filename -DestinationPath $tun2socks_path
        Remove-Item $zip_filename
        Move-Item (Join-Path $tun2socks_path "wintun\bin\$arch\wintun.dll") $tun2socks_path

        Add-ToPath $tun2socks_path

        Write-Host "[+] tun2socks installed"
    } catch {
        Write-Error "[-] Failed to install tun2socks: $($_.Exception)"
        exit 1
    }
}

function Start-DNSCrypt {
    Start-Service dnscrypt-proxy 
}

function Start-Tun2Socks {
    try {
        if ($proc = Get-Process "tun2socks" -ErrorAction SilentlyContinue) {
            $proc | Stop-Process -Force
        }

        $timeout = 10
        $elapsed = 0
        $interval = 100
        $proc = Start-Process $tun2socks_binary -ArgumentList "-device $TUN_NAME -proxy socks5://127.0.0.1:1080 -interface $script:default_interface" -WindowStyle $WindowStyle -PassThru
        $script:TUN2SOCKS_PID = $proc.Id
        # Wait while tun2socks creates the net adapter
        while (-not (Get-NetAdapter -Name $TUN_NAME -ErrorAction SilentlyContinue) -and ($elapsed -lt ($timeout * 1000))) {
            Start-Sleep -Milliseconds $interval
            $elapsed += $interval
        }
        if (-not (Get-NetAdapter -Name $TUN_NAME -ErrorAction SilentlyContinue)) {
            Write-Error "[-] tun2socks is not creating $TUN_NAME interface: $($_.Exception)"
            Start-Cleanup
            exit 1
        }
    } catch {
        Write-Error "[-] Failed to start tun2socks: $($_.Exception)"
        exit 1
    }
}
function Start-Xray {
    try {
        if ($proc = Get-Process "xray" -ErrorAction SilentlyContinue) {
            $proc | Stop-Process -Force
        }

        $proc = Start-Process $xray_binary -ArgumentList "--config `"$xray_config`"" -WindowStyle $WindowStyle -PassThru
        $script:XRAY_PID = $proc.Id
    } catch {
        Write-Error "[-] Failed to start Xray-core: $($_.Exception)"
        exit 1
    }
}
function Stop-Xray {
    Write-Host "[~] Stopping Xray-core"
    try {
        Stop-Process -Id $script:XRAY_PID -Force
    } catch {
        Write-Error "[-] Failed to stop Xray-core"
    }
}
function Stop-Tun2Socks {
    Write-Host "[~] Stopping tun2socks"
    try {
        Stop-Process -Id $script:TUN2SOCKS_PID -Force
    } catch {
        Write-Error "[-] Failed to stop tun2socks"
    }
}
function Set-XrayConfig {
    Copy-Item $Config $xray_config

    $json_content = Get-Content -Path $xray_config -Raw
    $json_object = $json_content | ConvertFrom-Json

    # Fix freedom infinite loop
    $freedom_outbound = $json_object.outbounds | Where-Object { $_.protocol -eq "freedom" }
    if ($freedom_outbound) {
        $freedom_outbound | Add-Member -MemberType NoteProperty -Name "sendThrough" -Value $script:default_interface_ip
    } else {
        Write-Host "[!] The 'freedom' outbound was not found in the configuration."
        exit
    }

    # DNSCrypt servers go through freedom
    if (-not ($json_object.PSObject.Properties.Name -contains 'routing')) {
        $json_object | Add-Member -MemberType NoteProperty -Name 'routing' -Value ([PSCustomObject]@{})
    }

    if (-not ($json_object.routing.PSObject.Properties.Name -contains 'rules')) {
        $json_object.routing | Add-Member -MemberType NoteProperty -Name 'rules' -Value @()
    }

    $dnscrypt_servers = Get-DNSCryptServers

    $json_object.routing.rules += [PSCustomObject]@{
        "type" = "field"
        "source" = @("127.0.0.1")
        "ip" = $dnscrypt_servers
        "network" = "udp,tcp"
        "outboundTag" = "direct"
    }

    # -Torify
    if ($Torify) {
        $tor_outbound = @{
            "tag" = "tor"
            "protocol" = "socks"
            "settings" = @{
                "servers" = @(
                    @{
                        "address" = "127.0.0.1"
                        "port" = 9050
                    }
                )
            }
            "streamSettings" = @{
                "sockopt" = @{
                    "dialerProxy" = "proxy"
                }
            }
        }

        # Add the new outbound as the first outbound in the outbounds array
        $json_object.outbounds = @($tor_outbound) + $json_object.outbounds
    }

    # Save content
    $new_json_content = $json_object | ConvertTo-Json -Depth 10
    Set-Content -Path $xray_config -Value $new_json_content
}

function Find-AddressInXrayConfig {
    param (
        [string]$Config
    )
    $config_obj = Get-Content -Path $Config -Raw | ConvertFrom-Json
    $outbounds = $config_obj.outbounds
    foreach ($outbound in $outbounds) {
        $settings = $outbound.settings
        if ($settings.PSObject.Properties.Name -contains "vnext") {
            return $settings.vnext[0].address
        } else {
            return $settings.address
        }
    }
}
function Get-IPFromAddress {
    param (
        [Parameter(Mandatory)]
        [string]$Address
    )
    # Regex for IPv4
    $ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Regex for IPv6
    $ipv6_regex='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
    # Regex for domain
    $domain_regex='^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'

    if ($Address -match $ipv4_regex) {
        return $Address
    }
    elseif ($Address -match $ipv6_regex) {
        return $Address
    }
    elseif ($Address -match $domain_regex) {
        # In case dnscrypt-proxy is just restarted, we have to wait until it comes online
        $tries = 0
        while ($true) {
            if ($tries -gt 5) {
                Write-Host "[-] Can't make DNS requests through DNSCrypt-proxy, exiting"
                exit 1
            }
        
            try {
                $dns_request = Resolve-DnsName -Name $Address -ErrorAction Stop
                $ip = $dns_request.IPAddress | Select-Object -First 1
                return $ip
            } catch {
                if ($_.Exception.Message -match "DNS name does not exist") {
                    Write-Error "[x] $Address does not exist"
                    exit 1
                }
                Start-Sleep -Seconds 1
                $tries++
                continue
            }
        }
    } 
    else {
        Write-Error "[x] $Address is an invalid address"
        exit 1
    }
}

function Get-DNSCryptServers {
    if (-not ($script:dnscrypt_servers)) {
        $dnscrypt_output = & "dnscrypt-proxy" -list -json 2>&1
        $stderr = $dnscrypt_output | ?{ $_ -is [System.Management.Automation.ErrorRecord] }
        $stdout = $dnscrypt_output | ?{ $_ -isnot [System.Management.Automation.ErrorRecord] }
        $servers = $stdout | ConvertFrom-Json
        foreach ($server in $servers) {
            if ($server.addrs) {
                $script:dnscrypt_servers.Add($server.addrs)
            }
        }
    }

    return $script:dnscrypt_servers
}

function Get-XrayIP {
    if (-not ($script:xray_address)) {
        $script:xray_address = Find-AddressInXrayConfig $Config
    }
    if (-not ($script:xray_ip)) {
        $script:xray_ip = Get-IPFromAddress $xray_address
    }
    return $script:xray_ip
}
function Add-Routes {
    Write-Host "[~] Adding routes..."

    try {
        $xray_ip = Get-XrayIP
        netsh interface ipv4 set address name="$TUN_NAME" source=static addr=192.168.123.1 mask=255.255.255.0 1>$null
        netsh interface ipv4 add route 0.0.0.0/0 "$TUN_NAME" 192.168.123.1 metric=1 1>$null
        New-NetRoute -DestinationPrefix "$xray_ip/32" -NextHop $script:gateway_ip -InterfaceAlias $script:default_interface -ErrorAction SilentlyContinue

        # $dnscrypt_servers = Get-DNSCryptServers
        # foreach ($server in $dnscrypt_servers) {
        #     New-NetRoute -DestinationPrefix "$server/32" -NextHop $script:gateway_ip -InterfaceAlias $script:default_interface -ErrorAction SilentlyContinue | Out-Null
        # }

    } catch {
        Write-Error "[-] Failed to add routes: $($_.Exception)"
        Start-Cleanup
        exit 1
    }
    
    Write-Host "[+] Added routes"
}

function Remove-Routes {
    Write-Host "[~] Deleting routes..."

    try {
        netsh interface ipv4 delete route 0.0.0.0/0 interface="$TUN_NAME" 1>$null
    } catch {
        Write-Error "[-] Failed to delete routes: $($_.Exception)"
        exit 1
    }

    Write-Host "[+] Deleted routes"
}

function Enable-Killswitch {
    Write-Host "[~] Turning on killswitch..."

    $xray_ip = Get-XrayIP
    $dnscrypt_servers = Get-DNSCryptServers -join ","

    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    New-NetFirewallRule -DisplayName "svoboda.center VPN Kill Switch - Allow VPN Interface Traffic" `
                    -Direction Outbound `
                    -Action Allow `
                    -InterfaceAlias $TUN_NAME `
                    -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "svoboda.center VPN Kill Switch - Allow VPN IP Traffic" `
                    -Direction Outbound `
                    -Action Allow `
                    -RemoteAddress $xray_ip `
                    -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "svoboda.center VPN Kill Switch - Allow Freedom Traffic" `
                    -Direction Outbound `
                    -Action Allow `
                    -Program $xray_binary `
                    -LocalAddress $script:default_interface_ip `
                    -Profile Any | Out-Null

    Write-Host "[+] Killswitch is on"
}

function Disable-Killswitch {
    Write-Host "[~] Turning off killswitch..."

    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
    Remove-NetFirewallRule -DisplayName "svoboda.center VPN Kill Switch*"

    Write-Host "[+] Killswitch is off"
}

function Start-Cleanup {
    Write-Host "[~] Cleaning up..."

    Remove-Routes
    Stop-Xray
    Stop-Tun2Socks
    Disable-Killswitch
    Stop-Transcript -ErrorAction SilentlyContinue
}

function Install-Setup {
    if (-not (Test-Path -Path $tmp_dir)) {
        New-Item -ItemType Directory -Path $tmp_dir | Out-Null
    } 

    if (-not (Test-Installed "dnscrypt-proxy")) {
        Install-DNSCryptProxy
    }

    if (-not (Test-Installed "xray")) {
        Install-Xray
    }

    if (-not (Test-Installed "tun2socks")) {
        Install-Tun2socks
    }
}

function Uninstall-Setup {
    Remove-Item -Path $tmp_dir -Recurse -ErrorAction SilentlyContinue | Out-Null

    dnscrypt-proxy -service uninstall 2> $null
    Set-DnsClientServerAddress -InterfaceAlias $script:default_interface -ServerAddresses ("9.9.9.9", "9.9.9.11")

    Remove-Item -Path $dnscrypt_proxy_download_path -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-FromPath $dnscrypt_proxy_final_path

    Remove-Item -Path $xray_path -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-FromPath $xray_path

    Remove-Item -Path $tun2socks_path -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-FromPath $tun2socks_path

    # Cleanup
    Remove-Routes
    Disable-Killswitch
}

function Update-App {
    if (-not (Test-Installed "git")) {
        Write-Host "[!] Can't update: git is required"
        return
    }
    if (-not (Test-Path ".git")) {
        Write-Host "[!] Can't update: no .git directory found"
        return
    }

    Write-Host "[~] Checking for updates..."

    git fetch origin

    # Check if local branch is behind remote
    $local_commit = git rev-parse HEAD
    $remote_commit = git rev-parse '@{u}'

    if ($local_commit -ne $remote_commit) {
        Write-Host "[~] New updates detected, pulling changes..."

        git pull --rebase

        Write-Host "[+] Updated, restarting"

        & "$SCRIPT_PATH" "$SCRIPT_ARGS"
    } else {
        Write-Host "[?] Already up-to-date"
    }

}

function Install-VPNService {
    try {
        New-Item -ItemType Directory -Path $TASK_DIR -ErrorAction Stop | Out-Null
    } catch {
        if ($_.Exception.Message -notmatch "already exists") {
            Write-Error "[-] Failed to create directory: $_"
        }
    }

    # Copy files
    Copy-Item -Path $SCRIPT_DIR\* -Destination $TASK_DIR -Recurse -Force

    # Create task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle $WindowStyle -File `"$TASK_DIR\run.ps1`" -Service -Log `"$TASK_LOG`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable

    try {
        if ($existing_task = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue) {
            $existing_task | Unregister-ScheduledTask -Confirm:$false
        }
        Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    } catch {
        if ($_.Exception.Message -notmatch "already exists") {
            Write-Error "[-] Failed to register scheduled task: $_"
        }
    }

    Start-VPNService
}

function Uninstall-VPNService {
    Remove-Item -Path $TASK_DIR -Recurse -Force

    Stop-ScheduledTask -TaskName $TASK_NAME
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
}

function Stop-VPNService {
    # Stop-ScheduledTask can't stop the task gracefully
    # Main script listens to this event and exits on .Set()
    $exit_event = [System.Threading.EventWaitHandle]::OpenExisting($TASK_EVENT_NAME)
    if (-not $exit_event) {
        Write-Host "[!] Task isn't running"
        return 1
    }
    $exit_event.Set() | Out-Null
    $exit_event.Dispose()
}
function Start-VPNService {
    try {
        Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction Stop
    } catch [Microsoft.Management.Infrastructure.CimException] {
        if ($_.Exception.Message -match "The system cannot find the file specified") {
            Write-Host "[x] Service not found."
            Write-Host "[?] Run .\run.ps1 -Install first."
        } else {
            Write-Host "[-] Unexpected error: $($_.Exception.Message)"
        }
        exit 1
    }
    $exit_event = [System.Threading.EventWaitHandle]::New($false, [System.Threading.EventResetMode]::ManualReset, $TASK_EVENT_NAME)
}

function Start-Main {
    # Init network vars before doing networking
    $script:default_interface = Get-DefaultInterfaceAlias
    $script:default_interface_ip = Get-InterfaceIP -InterfaceAlias $script:default_interface
    $script:gateway_ip = Get-GatewayIP -InterfaceAlias $script:default_interface

    # Internet is not required yet
    if ($KillswitchOff) {
        Disable-Killswitch
        exit 0
    }
    if ($KillswitchOn) {
        Enable-Killswitch
        exit 0
    }
    if ($Uninstall) {
        Uninstall-VPNService
        Uninstall-Setup
        Write-Host "[+] Uninstalled"
        exit 0
    }
    if ($Stop) {
        Stop-VPNService
        Write-Host "[+] Stopped background task $TASK_NAME"
        exit 0
    }
    if ($Start) {
        Start-VPNService
        Write-Host "[+] Started background task $TASK_NAME"
        exit 0
    }

    if ($Service) {
        Write-Host "[~] Running in a service mode..."
        try {
            $exit_event = [System.Threading.EventWaitHandle]::OpenExisting($TASK_EVENT_NAME)
        } catch {
            $exit_event = [System.Threading.EventWaitHandle]::New($false, [System.Threading.EventResetMode]::ManualReset, $TASK_EVENT_NAME)
        }
    }

    # Now internet is required
    if (Get-NetFirewallRule -DisplayName "svoboda.center VPN Kill Switch*") {
        Disable-Killswitch
    }
    Write-Host "[~] Testing internet connection..."
    while ($true) {
        $ping_result = Test-Connection -ComputerName 9.9.9.9 -Count 1 -Quiet
        if (-not $ping_result) {
            Write-Host "[-] Waiting for internet connection..."
            Start-Sleep 5
        } else {
            break
        } 
    }

    if ($Install) {
        Install-Setup
        Install-VPNService
        Write-Host "[+] Installed as a task '$TASK_NAME'"
        Write-Host "[?] Configuration file: $TASK_DIR\config.json"
        Write-Host "[?] Log file: $TASK_LOG"
        Write-Host "[?] Stop VPN with .\run.ps1 -Stop"
        exit 0
    }

    Install-Setup

    Write-Host "[~] Starting main process..."

    Update-App

    if (-not ($NoFilter)) {
        Receive-DNSBlacklist
    }
    $is_dns_blacklist_enabled = Test-DNSBlacklistEnabled
    if (-not ($NoFilter) -and -not ($is_dns_blacklist_enabled)) {
        Add-DNSBlacklist
    }   
    elseif ($NoFilter -and $is_dns_blacklist_enabled) {
        Remove-DNSBlacklist
    }

    Set-SystemDNS

    if (Select-String -Path $Config -Pattern "geoip:") {
        Receive-GeoIP
    }

    if (Select-String -Path $Config -Pattern "geosite:") {
        Receive-Geosite
    }

    Set-XrayConfig
    Start-DNSCrypt
    Start-Xray
    Start-Tun2Socks
    Add-Routes

    if (-not ($Nokillswitch)) {
        Enable-Killswitch
    }

    Write-Host "[+] Started main process, press CTRL+C to exi"

    # Loop until Ctrl+C 
    try {
        $exit_event.Reset() | Out-Null
        while ($true) {
            if ($Service -and $exit_event.WaitOne(1000)) {
                Write-Host "[!] Stop signal detected. Exiting..."
                break
            } else {
                Start-Sleep 1
            }
        }
    } finally {
        Write-Host "[~] Exiting main process"
        Start-Cleanup
        exit
    }
}

Start-Main