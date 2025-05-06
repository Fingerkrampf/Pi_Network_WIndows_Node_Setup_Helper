<#
  Dieses Skript ist freie Software: Sie können es unter den Bedingungen
  der GNU General Public License, wie von der Free Software Foundation veröffentlicht,
  weiterverbreiten und/oder modifizieren, entweder gemäß Version 3 der Lizenz oder
  (nach Ihrer Wahl) jeder späteren Version.

  Dieses Skript wird in der Hoffnung verteilt, dass es nützlich sein wird,
  aber OHNE JEDE GEWÄHRLEISTUNG – sogar ohne die implizite Gewährleistung
  der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.

  Siehe die GNU General Public License für weitere Details.
  <https://www.gnu.org/licenses/>.
#>

<#
--------------------------------------------------------------------------------
Pi Network Windows Node Setup Helper – von Fingerkrampf / PiNetzwerkDeutschland.de
VER 2025-05-06  (komplett automatisiertes Installationsskript für den Betrieb eines Pi Network Windows Nodes + IPv6 Lösung in Verbindung mit einem gemieteten vServer, PS-5-kompatibel)
HINWEIS: Die Nutzung und Ausführung des Skripts erfolgt auf eigene Verantwortung und Gefahr.
Das Skript dient lediglich der Vereinfachung des Einrichtungsprozesses.
Für den Inhalt, die Sicherheit oder Funktionsweise der installierten Programme wird keine Haftung übernommen.
Alle Downloads erfolgen ausschließlich von offiziellen Quellen!
--------------------------------------------------------------------------------
 Menüpunkte:
   1) Windows-Updates suchen
   2) WSL2 einrichten & aktivieren
   3) Docker Desktop downloaden & installieren (winget)
   4) Pi Network Node downloaden & installieren (Direkt-Download)
   5) Windows Firewall-Ports 31400-31409 freigeben
   6) PuTTY downloaden & installieren (winget)
   7) WireGuard Client downloaden & installieren (winget) & Schlüssel generieren
   8) WireGuard Server verbinden & einrichten & Client automatisch verbinden
   9) PiCheck downloaden & entpacken & starten
  10) Hilfe / Info
  11) Beenden
--------------------------------------------------------------------------------
#>

# === Admin-Check ===
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ((Read-Host 'Administratorrechte erforderlich. Neu starten? (J/N)') -match '^[Jj]$') {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    }
    exit
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# === Pfad-Funktionen ===

function Is-WSL2Enabled {
    $wsl = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    $vm  = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    return ($wsl.State -eq "Enabled" -and $vm.State -eq "Enabled")
}

function Get-WGDir {
    foreach ($path in 'C:\Program Files\WireGuard', 'C:\Program Files (x86)\WireGuard') {
        if (Test-Path (Join-Path $path 'wg.exe')) { return $path }
    }
    return $null
}

function Get-PuTTYDir {
    foreach ($path in 'C:\Program Files\PuTTY', 'C:\Program Files (x86)\PuTTY') {
        if ((Test-Path (Join-Path $path 'putty.exe')) -and (Test-Path (Join-Path $path 'plink.exe')) -and (Test-Path (Join-Path $path 'pscp.exe'))) {
            return $path
        }
    }
    return $null
}

function Are-NodeFirewallRulesPresent {
    $requiredPorts = 31400..31409
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'PiNode_TCP_In_*' -or $_.DisplayName -like 'PiNode_TCP_Out_*' }

    $existingPorts = @()  # leeres Array initialisieren
    foreach ($rule in $rules) {
        if ($rule.DisplayName -match '_(\d+)$') {
            $existingPorts += [int]$matches[1]
        }
    }

    return ($requiredPorts | Where-Object { $existingPorts -contains $_ }).Count -eq $requiredPorts.Count
}


function Refresh-InstallationStatus {
    $global:DockerInstalled     = (Get-Command docker -ErrorAction SilentlyContinue) -ne $null
    $global:PiNodeInstalled = @(
    "$env:LOCALAPPDATA\Programs\pi-network-desktop"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
    $global:PuTTYInstalled      = Get-PuTTYDir
    $global:WireGuardInstalled  = Get-WGDir
$global:WSL2Enabled = Is-WSL2Enabled
$global:WGKeysPresent = Check-WGKeysExist
$global:FirewallPortsOpen = Are-NodeFirewallRulesPresent
}

# === Installationsfunktionen ===

function Do-WindowsUpdates {
    Write-Host 'Suche nach Windows Updates …' -ForegroundColor Cyan
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
    if ($searchResult.Updates.Count -eq 0) {
        Write-Host 'Keine neuen Updates gefunden.' -ForegroundColor Green
 pause
        return
    }

    Write-Host "$($searchResult.Updates.Count) Updates gefunden." -ForegroundColor Yellow
    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $searchResult.Updates) {
        if (-not $update.EulaAccepted) {
            $update.AcceptEula()
        }
        $updatesToDownload.Add($update) | Out-Null
    }

    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $updatesToDownload
    $downloader.Download()

    Write-Host 'Updates heruntergeladen. Installation startet …' -ForegroundColor Cyan

    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $updatesToDownload
    $installationResult = $installer.Install()

    Write-Host "Installation abgeschlossen. Ergebniscode: $($installationResult.ResultCode)" -ForegroundColor Green
 pause
}

function Do-EnableWSL2 {
    $flagPath = "$env:ProgramData\wsl2_setup_flag.txt"
    $scriptPath = $MyInvocation.MyCommand.Definition
    $autostartBatPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ResumeWSL2Setup.bat"

    if (Test-Path $flagPath) {
        Write-Host "`n Fortsetzungs-Flag erkannt – Setup wird fortgesetzt..." -ForegroundColor Cyan

        try {
            wsl --set-default-version 2
            Write-Host "`nWSL2 wurde als Standardversion gesetzt." -ForegroundColor Green
        } catch {
            Write-Warning "Fehler beim Setzen der Standardversion: $_"
        }

        # Aufräumen
        Remove-Item $flagPath -Force -ErrorAction SilentlyContinue
        Remove-Item $autostartBatPath -Force -ErrorAction SilentlyContinue
        Pause
        return
    }

    Write-Host "`n Prüfe WSL2-Status..." -ForegroundColor Cyan

    $wslEnabled = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -eq "Enabled"
    $vmEnabled  = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -eq "Enabled"

    if ($wslEnabled -and $vmEnabled) {
        Write-Host "WSL2 ist bereits vollständig aktiviert." -ForegroundColor Green
        Pause
        return
    }

    Write-Host "`nAktiviere benötigte Windows-Features für WSL2..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -All
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All

    Set-Content -Path $flagPath -Value "resume"

    $batContent = "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""
    Set-Content -Path $autostartBatPath -Value $batContent -Encoding ASCII

    Write-Host "`nSystem wird neu gestartet – Setup wird beim nächsten Login automatisch fortgesetzt." -ForegroundColor Yellow
    Pause
    Restart-Computer -Force
}


function Do-InstallWireGuard {
    Write-Host "Installiere WireGuard mit winget..." -ForegroundColor Cyan

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }

        Write-Host "Starte Silent-Installation von WireGuard..."
        winget install -e --id WireGuard.WireGuard --silent --accept-package-agreements --accept-source-agreements
        Start-Process "C:\Program Files\Wireguard\Wireguard.exe"

        Write-Host "WireGuard wurde erfolgreich installiert und gestartet!" -ForegroundColor Green

    $wgDir = Get-WGDir
        if ($wgDir) {
            Gen-WGKeys $wgDir
        } else {
            Write-Warning "WireGuard-Verzeichnis nicht gefunden."
        }
    }
    catch {
        Write-Host "FEHLER: $_" -ForegroundColor Red
        Write-Host "Tipp: Stellen Sie sicher, dass winget verfügbar und aktuell ist." -ForegroundColor Yellow
    }

    Pause
}

function Do-FirewallPorts {
    Write-Host 'Setze Firewall-Regeln für Ports 31400-31409 …' -ForegroundColor Cyan
    foreach ($p in 31400..31409) {
        New-NetFirewallRule -DisplayName "PiNode_TCP_In_$p"  -Direction Inbound  -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName "PiNode_TCP_Out_$p" -Direction Outbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null
    }
    Write-Host 'Firewall-Regeln erstellt.' -ForegroundColor Green
    Pause
}

function Do-InstallPuTTY {
    Write-Host 'Installiere PuTTY...' -ForegroundColor Cyan
    Start-Process 'winget' -ArgumentList 'install', '--id', 'PuTTY.PuTTY', '-e', '--accept-source-agreements', '--accept-package-agreements' -Wait
    Pause
}

function Do-InstallDocker {
    Write-Host "Installiere Docker Desktop.." -ForegroundColor Cyan

    try {
        # Überprüfen, ob winget verfügbar ist
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }

        Write-Host "Starte Silent-Installation von Docker Desktop..."
        winget install -e --id Docker.DockerDesktop --silent --accept-package-agreements --accept-source-agreements
        Start-Sleep -Seconds 5 
        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

        Write-Host "Docker Desktop wurde erfolgreich installiert und gestartet!" -ForegroundColor Green
    }
    catch {
        Write-Host "FEHLER: $_" -ForegroundColor Red
        Write-Host "Tipp: Stellen Sie sicher, dass winget verfügbar und aktuell ist." -ForegroundColor Yellow
    }

    Pause
}

function Do-InstallPiNode {
    Write-Host "Installiere Pi Network Node Software.." -ForegroundColor Cyan
    $url = "https://downloads.minepi.com/Pi%20Network%20Setup%200.5.0.exe"
    $installerPath = "$env:TEMP\PiNetworkSetup050.exe"
    & curl.exe -L $url -o $installerPath
    Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait
    Write-Host "Pi Network Node erfolgreich installiert und gestartet!" -ForegroundColor Green
 pause
}

function DownloadAndStartPiCheck {
    Write-Host 'Lade PiCheck-Archiv mit curl herunter ...' -ForegroundColor Cyan
    $url = "https://github.com/muratyurdakul75/picheck/archive/refs/heads/main.zip"
    $tempPath = "$env:TEMP"
    $zipPath = Join-Path $tempPath "picheck-main.zip"
    $unzipPath = Join-Path $tempPath "picheck-unpacked"
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $targetPath = Join-Path $desktopPath "PiCheck"
    if (Test-Path $unzipPath) { Remove-Item -Path $unzipPath -Recurse -Force }
    if (Test-Path $targetPath) { Remove-Item -Path $targetPath -Recurse -Force }
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "curl.exe wurde nicht gefunden. Bitte stelle sicher, dass es installiert ist."
        return
    }

    $curlCmd = "curl.exe -L -o `"$zipPath`" `"$url`""
    cmd.exe /c $curlCmd

    if (-not (Test-Path $zipPath)) {
        Write-Warning "Download fehlgeschlagen oder ZIP-Datei nicht vorhanden."
        return
    }

    Write-Host "Entpacke Hauptarchiv ..." -ForegroundColor Cyan
    Expand-Archive -Path $zipPath -DestinationPath $unzipPath -Force

    $versionZips = Get-ChildItem -Path $unzipPath -Recurse -Filter "*.zip" | ForEach-Object {
        if ($_.Name -match '(\d+\.\d+\.\d+)') {
            [PSCustomObject]@{
                File     = $_
                Version  = [version]$matches[1]
            }
        }
    }

    if (-not $versionZips) {
        Write-Warning "Keine gültigen PiCheck-Versionen gefunden."
        return
    }

    $latest = $versionZips | Sort-Object Version -Descending | Select-Object -First 1

    Write-Host "Entpacke Version: $($latest.File.Name)" -ForegroundColor Cyan
    Expand-Archive -Path $latest.File.FullName -DestinationPath $targetPath -Force

    $exePath = Get-ChildItem -Path $targetPath -Filter "picheck.exe" -Recurse | Select-Object -First 1
    if (-not $exePath) {
        Write-Warning "picheck.exe wurde nicht gefunden."
        return
    }

    $vcInstaller = Get-ChildItem -Path $targetPath -Filter "VC_redist.x64.exe" -Recurse | Select-Object -First 1
    if ($vcInstaller) {
        Write-Host "Installiere VC_redist.x64.exe im Silent-Mode ..." -ForegroundColor Cyan
        Start-Process -FilePath $vcInstaller.FullName -ArgumentList "/quiet", "/norestart" -Wait
    } else {
        Write-Warning "VC_redist.x64.exe nicht gefunden."
    }

    Write-Host "Starte picheck.exe /auto ..." -ForegroundColor Green
    Start-Process -FilePath $exePath.FullName -ArgumentList "/auto"

    Remove-Item -Path $zipPath -Force
    Remove-Item -Path $unzipPath -Recurse -Force
 pause
}

function Check-WGKeysExist {
    $dir = Get-WGDir
    if (-not $dir) { return $false }
    $keyDir = Join-Path $dir 'keys'
    return (Test-Path (Join-Path $keyDir 'wg_private.key')) -and (Test-Path (Join-Path $keyDir 'wg_public.key'))
}

# === SSH Hostkey löschen und automatisch annehmen ===
function Remove-AllHostKeysForIP($serverIp) {
    $hostKeyPath = "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"
    $prefixes = @('rsa2', 'dsa', 'ecdsa', 'ed25519', 'ssh-ed25519')
    foreach ($prefix in $prefixes) {
        $entryName = "${prefix}@22:$serverIp"
        Remove-ItemProperty -Path $hostKeyPath -Name $entryName -ErrorAction SilentlyContinue
    }
}

function Ensure-HostKeyAccepted {
    param (
        [string]$serverIp,
        [string]$user = "root",
        [string]$password = $null,
        [string]$privateKeyPath = $null
    )

    $pu = Get-PuTTYDir
    if (-not $pu) { Write-Warning "PuTTY nicht gefunden."; return }
    Remove-AllHostKeysForIP -serverIp $serverIp
    $plink = Join-Path $pu 'plink.exe'
    Write-Host "Akzeptiere SSH-Hostkey von $serverIp automatisch..." -ForegroundColor Yellow

    # Temporäre Antwortdatei für Hostkey-Bestätigung
    $responseFile = [System.IO.Path]::GetTempFileName()
    "y`n" | Out-File -FilePath $responseFile -Encoding ASCII

    # Argumente je nach Methode zusammenstellen
    $args = @()
    if ($password) {
        $args += "-pw", $password
    } elseif ($privateKeyPath) {
        $args += "-i", "`"$privateKeyPath`""
    }

    $args += "$user@$serverIp", "exit"

    # plink starten
    $process = Start-Process -FilePath $plink -ArgumentList $args -Wait -NoNewWindow -RedirectStandardInput $responseFile -PassThru
    Remove-Item $responseFile -Force

    if ($process.ExitCode -ne 0) {
        Write-Warning "Fehler beim Akzeptieren des Hostkeys für $serverIp (Exit-Code: $($process.ExitCode))"
    }
}

function Convert-OpenSSHKeyToPPK {
    param (
        [string]$opensshKeyPath,
        [string]$puttygenPath,
        [string]$ppkOutPath
    )

    if (-not (Test-Path $puttygenPath)) {
        Write-Error "puttygen.exe nicht gefunden. Bitte sicherstellen, dass PuTTY installiert ist."
        return $null
    }

    Write-Host "Konvertiere OpenSSH-Key nach PuTTY-Format (.ppk)..." -ForegroundColor Cyan
    & $puttygenPath "`"$opensshKeyPath`"" -o "`"$ppkOutPath`"" | Out-Null

    if (Test-Path $ppkOutPath) {
        Write-Host "Konvertierung erfolgreich: $ppkOutPath" -ForegroundColor Green
        return $ppkOutPath
    } else {
        Write-Error "Konvertierung fehlgeschlagen."
        return $null
    }
}


# === WireGuard-Keys generieren ===
function Gen-WGKeys($dir) {
    $keyDir = Join-Path $dir 'keys'
    if (-not (Test-Path $keyDir)) { New-Item -Path $keyDir -ItemType Directory | Out-Null }
    $wgExe = Join-Path $dir 'wg.exe'
    $priv = & $wgExe genkey
    $pub = $priv | & $wgExe pubkey
    $priv | Out-File (Join-Path $keyDir 'wg_private.key') -Encoding ASCII
    $pub  | Out-File (Join-Path $keyDir 'wg_public.key') -Encoding ASCII
}

# === WireGuard-Server-Setup komplett ===
function Do-SetupWGServer {
    $wg = Get-WGDir
    $pu = Get-PuTTYDir
    if (-not $pu) { Write-Warning 'PuTTY nicht installiert.'; return }
    if (-not $wg) { Write-Warning 'WireGuard nicht installiert.'; return }

    $serverIp = Read-Host 'IPv4 Adresse des vServers'

$authChoice = Read-Host 'Authentifizierungsmethode? (pw für Passwort / key für SSH-Key)'
if ($authChoice -eq 'pw') {
    $cred = Read-Host 'Root-Passwort' -AsSecureString
    $pwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))
    Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -password $pwd
}
elseif ($authChoice -eq 'key') {
    if ($PSCommandPath) {
    $scriptDir = Split-Path -Parent $PSCommandPath
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

    $opensshKey = Join-Path $scriptDir 'id_ed25519'
    $ppkKey     = [System.IO.Path]::ChangeExtension($opensshKey, ".ppk")
    $ppkWasTemporary = $false

    if (-not (Test-Path $ppkKey)) {
        if (-not (Test-Path $opensshKey)) {
            Write-Error "SSH-Key '$opensshKey' nicht gefunden. Bitte im Skriptverzeichnis ablegen."
            return
        }

        $puttygen = Join-Path (Get-PuTTYDir) 'puttygen.exe'
        $convertedKey = Convert-OpenSSHKeyToPPK -opensshKeyPath $opensshKey -puttygenPath $puttygen -ppkOutPath $ppkKey
        if (-not $convertedKey) { return }
        $ppkWasTemporary = $true
    }

    Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -privateKeyPath $ppkKey

    if ($ppkWasTemporary) {
        Cleanup-TemporaryFiles -ppkPath $ppkKey
    }
}
else {
    Write-Error "Ungültige Auswahl. Bitte 'pw' oder 'key' eingeben."
    return
}


    $wgExe = Join-Path $wg 'wg.exe'
    $keyDir = Join-Path $wg 'keys'
    if (-not (Test-Path $keyDir)) { New-Item $keyDir -ItemType Directory | Out-Null }

    $clientPriv = & $wgExe genkey
    $clientPub = $clientPriv | & $wgExe pubkey
    $serverPriv = & $wgExe genkey
    $serverPub = $serverPriv | & $wgExe pubkey

    $clientPrivPath = Join-Path $keyDir 'wg_private.key'
    $clientPubPath  = Join-Path $keyDir 'wg_public.key'
    $clientPriv | Out-File $clientPrivPath -Encoding ASCII
    $clientPub  | Out-File $clientPubPath  -Encoding ASCII

    # Erstellen des Bash-Skripts für den Server
    $bash = @'
#!/bin/bash
set -euo pipefail
apt update -y
apt install -y wireguard iproute2 iptables curl ca-certificates gnupg

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
sysctl --system

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
umask 077

SERVER_PRIVATE="{{SERVER_PRIV}}"
SERVER_PUBLIC="{{SERVER_PUB}}"
CLIENT_PUBLIC="{{CLIENT_PUB}}"

DEFAULT_INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
SERVER_IP=$(curl -s https://ifconfig.me)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 192.168.200.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE
PostUp = iptables -A FORWARD -i %i -o $DEFAULT_INTERFACE -j ACCEPT; iptables -A FORWARD -i $DEFAULT_INTERFACE -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o $DEFAULT_INTERFACE -j ACCEPT; iptables -D FORWARD -i $DEFAULT_INTERFACE -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC
AllowedIPs = 192.168.200.2/32
EOF

wg-quick up wg0
systemctl enable wg-quick@wg0

echo "Firewall-Regeln einrichten..."
iptables -A INPUT -i $DEFAULT_INTERFACE -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i $DEFAULT_INTERFACE -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P INPUT DROP

iptables -A FORWARD -i wg0 -o $DEFAULT_INTERFACE -j ACCEPT
iptables -A FORWARD -i $DEFAULT_INTERFACE -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp -m multiport --dport 31400:31409 -j DNAT --to-destination 192.168.200.2

iptables -P FORWARD ACCEPT

'@

    $bash = $bash -replace '{{SERVER_PRIV}}', $serverPriv.Trim()
    $bash = $bash -replace '{{SERVER_PUB}}', $serverPub.Trim()
    $bash = $bash -replace '{{CLIENT_PUB}}', $clientPub.Trim()

    $tempScript = Join-Path $env:TEMP "wg_setup.sh"
    Set-Content -Path $tempScript -Value $bash -Encoding UTF8

    $pscp = Join-Path $pu 'pscp.exe'
    & $pscp -batch -pw $pwd $tempScript "root@${serverIp}:/tmp/wg_setup.sh"

    $plink = Join-Path $pu 'plink.exe'
    & $plink -batch -pw $pwd "root@${serverIp}" "bash /tmp/wg_setup.sh"

    # Erstellung der client.conf auf dem lokalen System des Clients
    $clientConfPath = Join-Path $wg 'client.conf'

    $clientConfContent = @"
[Interface]
PrivateKey = $clientPriv
Address = 192.168.200.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $serverPub
Endpoint = ${serverIp}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@

    Set-Content -Path $clientConfPath -Value $clientConfContent -Encoding ASCII

    $clientConfPathFinal = "C:\Program Files\WireGuard\client.conf"

    Write-Host "Aktiviere WireGuard-Verbindung..." -ForegroundColor Cyan
    & "$env:ProgramFiles\WireGuard\wireguard.exe" /installtunnelservice $clientConfPathFinal

    Write-Host "WireGuard-Setup abgeschlossen und der Wireguard Tunnel ist nun aktiviert!" -ForegroundColor Green
    Write-Host "HINWEIS: Bitte beachten Sie, dass gegebenenfalls der WireGuard-UDP-Port 51820 sowie die TCP-Ports 31400 bis 31409 für den PI Network Nodes im Kundeninterface Ihres Serveranbieters freigegeben sein müssen bzw. bereits eingetragen sind!" -ForegroundColor RED

    Pause
}

# --- Menü ---
function Show-Menu {
    Clear-Host
    Refresh-InstallationStatus

    Write-Host '===[ Pi Network Windows Node Setup Helper Script ]===' -ForegroundColor Green
    Write-Host ''

    # === Gruppe 1–5: Basis-Setup ===
    Write-Host '1) Windows-Updates' -ForegroundColor Cyan

    if ($WSL2Enabled) {
        Write-Host "2) WSL2 (" -ForegroundColor Cyan -NoNewline
        Write-Host "aktiviert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "2) WSL2 einrichten" -ForegroundColor Cyan
    }

    if ($DockerInstalled) {
        Write-Host "3) Docker Desktop (" -ForegroundColor Cyan -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "3) Docker Desktop installieren" -ForegroundColor Cyan
    }

    if ($PiNodeInstalled) {
        Write-Host "4) Pi Network Node (" -ForegroundColor Cyan -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "4) Pi Network Node installieren" -ForegroundColor Cyan
    }

    if ($FirewallPortsOpen) {
        Write-Host "5) Firewall-Ports (" -ForegroundColor Cyan -NoNewline
        Write-Host "freigegeben" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "5) Firewall-Ports freigeben" -ForegroundColor Cyan
    }

    # === Gruppe 6–8: Netzwerk-Tools ===
    if ($PuTTYInstalled) {
        Write-Host "6) PuTTY (" -ForegroundColor Yellow -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Yellow
    } else {
        Write-Host "6) PuTTY installieren" -ForegroundColor Yellow
    }

    if ($WireGuardInstalled) {
        if ($WGKeysPresent) {
            Write-Host "7) WireGuard (" -ForegroundColor Yellow -NoNewline
            Write-Host "installiert, Schlüssel vorhanden" -ForegroundColor Green -NoNewline
            Write-Host ")" -ForegroundColor Yellow
        } else {
            Write-Host "7) WireGuard (" -ForegroundColor Yellow -NoNewline
            Write-Host "installiert, keine Schlüssel" -ForegroundColor Green -NoNewline
            Write-Host ")" -ForegroundColor Yellow
        }
    } else {
        Write-Host "7) WireGuard Windows Client installieren" -ForegroundColor Yellow
    }

    Write-Host '8) Automatisch WireGuard Server einrichten & Client verbinden' -ForegroundColor Yellow

    # === Gruppe 9: Analyse-Tool ===
    Write-Host '9) PiCheck herunterladen, entpacken und starten' -ForegroundColor White

    # === Gruppe 10–11: Info & Exit ===
    Write-Host '10) Hilfe / Info' -ForegroundColor DarkGreen
    Write-Host '11) Beenden' -ForegroundColor DarkGreen

    Write-Host ''
}


# --- Hauptschleife ---
while ($true) {
    Show-Menu
    $choice = Read-Host 'Auswahl'  
    switch ($choice) {
        '1'  { Do-WindowsUpdates }
        '2'  { Do-EnableWSL2 }
        '3'  { if (-not $DockerInstalled) { Do-InstallDocker } else { Write-Host 'Docker Desktop bereits installiert.' -ForegroundColor GREEN; Pause } }
        '4'  { if (-not $PiNodeInstalled) { Do-InstallPiNode } else { Write-Host 'Pi Network Node bereits installiert.' -ForegroundColor GREEN; Pause } }
        '5'  { Do-FirewallPorts }
        '6'  { if (-not $PuTTYInstalled) { Do-InstallPuTTY } else { Write-Host 'PuTTY bereits installiert.' -ForegroundColor GREEN; Pause } }
        '7'  { if (-not $WireGuardInstalled) { Do-InstallWireGuard } else { Write-Host 'WireGuard bereits installiert.' -ForegroundColor GREEN; Pause } }
        '8'  { Do-SetupWGServer }
        '9' { DownloadAndStartPiCheck }
        '10'  {
          Write-Host ' ' -ForegroundColor Green            
Write-Host 'Die Schritte 1 bis 5 unterstützen Sie bei der grundlegenden Einrichtung eines Pi Network Nodes.' -ForegroundColor Green
Write-Host 'Die Schritte 6 bis 8 helfen Ihnen dabei, einen WireGuard-Server unter Linux automatisch zu installieren und zu konfigurieren,' -ForegroundColor Green
Write-Host 'damit Ihr Pi Network Node über eine öffentliche IPv4-Adresse erreichbar ist und eingehende Verbindungen empfangen kann.' -ForegroundColor Green
Write-Host 'Schritt 9 lädt die aktuellste Version der PiCheck-Software herunter, entpackt sie und startet das Programm.' -ForegroundColor Green
Write-Host 'PiCheck ist ein nützliches Analysetool für alle Pi-Network-Node-Betreiber.' -ForegroundColor Green
Write-Host ' ' 
Write-Host 'Wenn Sie Unterstützung benötigen, erreichen Sie uns über folgenden Link in unserer Telegram Gruppe:' -ForegroundColor Green
Write-Host ' '
Write-Host 'Telegram: https://t.me/PiNetzwerkDeutschland' -ForegroundColor Yellow
Write-Host ' ' 
            Pause
        }
       '11' {
    Write-Host 'Setup beendet.'
    Stop-Process -Id $PID
}

        default { Write-Warning 'Ungültige Auswahl'; Pause }
    }
}

function Cleanup-TemporaryFiles {
    param (
        [string]$ppkPath = $null
    )

    try {
        if ($ppkPath -and (Test-Path $ppkPath)) {
            Write-Host "Bereinige temporäre Datei: $ppkPath" -ForegroundColor DarkGray
            Remove-Item $ppkPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Fehler beim Bereinigen temporärer Dateien: $_"
    }
}

