# svoboda.center xray client

Privacy focused Windows [xray](https://github.com/XTLS/Xray-core) client by https://svoboda.center

## Features

- DNS resolving via [DNSCrypt](https://dnscrypt.info), protecting user from DNS-based surveillance
- Automatically updated **DNS blacklist** for blocking ads/tracking/malware
- Robust **killswitch** prevents IP leaks
- **VPN > Tor chain** for enhanced privacy without the need to install Tor on client's machine
- Automatically updated **geosite.dat and geoip.dat** for xray routing

## Usage

Requirements: 
- powershell 5.1 (installed by default on windows 10/11)
- Administrative privileges

Start powershell.exe **as Administrator** and run code below

```powershell
# Clone the repository (if you have git installed)
git clone https://github.com/svobodacenter/xray-client-win
cd xray-client-win
# OR if you don't have git installed:
# Invoke-WebRequest -Uri https://github.com/svobodacenter/xray-client-win/archive/refs/heads/main.zip -OutFile main.zip -ErrorAction Stop 
# Expand-Archive main.zip -DestinationPath .
# cd xray-client-win-main/windows

# Run
.\run.ps1 -Config "path\to\config.json"
# OR just put config.json into this directory and run .\run.ps1
```

### Examples

- Route traffic through VPN and then Tor
    ```powershell
    .\run.ps1 -Torify
    ```
- No killswitch
    ```powershell
    .\run.ps1 -NoKillswitch
    ```
- Show help
    ```powershell
    .\run.ps1 -Help
    ```

If, for some reason, the client is killed and killswitch is still enabled, to disable it run: `.\run.ps1 -KillswitchOff`

## Questions

If you have any questions, feel free to reach out:

- **Website:** https://svoboda.center
- **Telegram:** https://t.me/svoboda_center
- **Twitter:** https://x.com/svobodacenter
- **Tox:** FC31427EC043880C59BB875209462462558941F570BEF564F15CB6473F4A6146272986AD2CF8
- **Email:** svobodacenter@mailum.com
- **PGP:** https://svoboda.center/pgp.asc

## License

This project is licensed under the Mozilla Public License Version 2.0. See the [LICENSE](LICENSE) file for more details.

## Credits

- [XTLS](https://github.com/XTLS)
- [DNSCrypt](https://github.com/DNSCrypt)
- [xjasonlyu](https://github.com/xjasonlyu)
- [wintun](https://www.wintun.net)