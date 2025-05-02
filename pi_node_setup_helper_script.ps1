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
VER 2025-05-02  (komplett automatisiertes Installationsskript für den Betrieb eines Pi Network Windows Nodes + IPv6 Lösung in Verbindung mit einem vServer, PS-5-kompatibel)
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

function Refresh-InstallationStatus {
    $global:DockerInstalled     = (Get-Command docker -ErrorAction SilentlyContinue) -ne $null
    $global:PiNodeInstalled = @(
    "$env:LOCALAPPDATA\Programs\pi-network-desktop"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
    $global:PuTTYInstalled      = Get-PuTTYDir
    $global:WireGuardInstalled  = Get-WGDir
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
    $flagPath = "C:\Windows\Temp\wsl_setup_flag.txt"
    $taskName = "ResumeWSL2Setup"

    if (Test-Path $flagPath) {
        Remove-Item $flagPath -Force
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        Write-Host "WSL2 Setup nach Neustart fortgesetzt." -ForegroundColor Green
        wsl --set-default-version 2
        pause
        return
    }

    $wslEnabled = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -eq "Enabled"
    $vmEnabled  = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -eq "Enabled"

    if ($wslEnabled -and $vmEnabled) {
        Write-Host "WSL2 und VirtualMachinePlatform sind bereits aktiviert." -ForegroundColor Green
        pause
        return
    }

    Write-Host 'Aktiviere Windows-Features für WSL2 …' -ForegroundColor Cyan
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -All
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All

    New-Item -ItemType File -Path $flagPath -Force | Out-Null

    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description "Fortsetzung WSL2 Setup" -Force
    } catch {
        Write-Warning "Konnte geplanten Task nicht erstellen: $_"
        pause
        return
    }

    Write-Host 'Neustart erforderlich – Rechner wird jetzt neu gestartet …' -ForegroundColor Yellow
    pause
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

function Ensure-HostKeyAccepted($serverIp, $user = "root", $password) {
    $pu = Get-PuTTYDir
    if (-not $pu) { Write-Warning "PuTTY nicht gefunden."; return }
    Remove-AllHostKeysForIP -serverIp $serverIp
    $plink = Join-Path $pu 'plink.exe'
    Write-Host "Akzeptiere SSH-Hostkey von $serverIp automatisch..." -ForegroundColor Yellow
    
    # Erstellen einer temporären Antwortdatei für die automatische Bestätigung
    $responseFile = [System.IO.Path]::GetTempFileName()
    "y`n" | Out-File -FilePath $responseFile -Encoding ASCII
    
    # Plink mit der Antwortdatei ausführen
    $process = Start-Process -FilePath $plink -ArgumentList "-pw", $password, "$user@${serverIp}", "exit" -Wait -NoNewWindow -RedirectStandardInput $responseFile -PassThru
    
    # Temporäre Datei bereinigen
    Remove-Item $responseFile -Force
    
    # Überprüfen des Exit-Codes
    if ($process.ExitCode -ne 0) {
        Write-Warning "Fehler beim Akzeptieren des Hostkeys für $serverIp (Exit-Code: $($process.ExitCode))"
    }
}

# Hilfsfunktion um PuTTY-Verzeichnis zu finden
function Get-PuTTYDir {
    $paths = @(
        "${env:ProgramFiles}\PuTTY",
        "${env:ProgramFiles(x86)}\PuTTY",
        "$env:LOCALAPPDATA\Programs\PuTTY"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $path
        }
    }
    return $null
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
    $cred = Read-Host 'Root-Passwort' -AsSecureString
    $pwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))

    Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -password $pwd

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
    Write-Host "HINWEIS: Bitte beachten Sie, dass gegebenenfalls der WireGuard-UDP-Port 51820 sowie die TCP-Ports 31400 bis 31409 für die PI Network Nodes im Kundeninterface Ihres Serveranbieters freigegeben sein müssen bzw. bereits eingetragen sind!" -ForegroundColor RED

    Pause
}

# --- Menü ---
function Show-Menu {
    Clear-Host
    Refresh-InstallationStatus
    $dockerText = if ($DockerInstalled) { '3) Docker Desktop (installiert)' } else { '3) Docker Desktop installieren' }
    $piNodeText = if ($PiNodeInstalled) { '4) Pi Network Node (installiert)' } else { '4) Pi Network Node installieren' }
    $puttyText  = if ($PuTTYInstalled)  { '6) PuTTY (installiert)' } else { '6) PuTTY installieren' }
    $wgText     = if ($WireGuardInstalled) { '7) WireGuard (installiert)' } else { '7) WireGuard installieren' }

    Write-Host '===[ Pi Network Windows Node Setup Helper Script ]===' -ForegroundColor GREEN
    Write-Host ' '
    Write-Host '1) Windows-Updates'
    Write-Host '2) WSL2 einrichten'
    Write-Host $dockerText
    Write-Host $piNodeText
    Write-Host '5) Windows Firewall - Node Ports freigeben'
    Write-Host $puttyText
    Write-Host $wgText
    Write-Host '8) WireGuard-Server einrichten und Client verbinden'
    Write-Host '9) PiCheck herunterladen, entpacken und starten'
    Write-Host '10) Hilfe / Info'
    Write-Host '11) Beenden'
    Write-Host ' '
  
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
