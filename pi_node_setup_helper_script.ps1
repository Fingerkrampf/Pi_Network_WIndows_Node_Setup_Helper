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
VER 2025-05-07  (vollautomatisiertes PowerShell-5.1-kompatibles Setup-Skript für den Betrieb eines Pi Network Nodes
unter Windows inklusive WireGuard-Tunnel über einen gemieteten Root-Server mit öffentlicher IPv4 – mit Logging,
Fehlerbehandlung, Rückgängig-Funktionen, Menüführung und vollständiger Kontrolle.)

HINWEIS: Die Nutzung und Ausführung des Skripts erfolgt auf eigene Verantwortung und Gefahr.
Das Skript dient lediglich der Vereinfachung des Einrichtungsprozesses.
Für den Inhalt, die Sicherheit oder Funktionsweise der installierten Programme wird keine Haftung übernommen.
Alle Downloads erfolgen ausschließlich von offiziellen Quellen!
--------------------------------------------------------------------------------

 Menüpunkte (automatisch aktualisierter Status in Echtzeit):
 
   1) Windows-Updates suchen & installieren (COM-API) + Logging, ExitCode-Auswertung
   2) WSL2 einrichten & aktivieren mit Neustart und Fortsetzungsmechanismus
   3) Docker Desktop downloaden & installieren (winget) mit ExitCode-Handling
   4) Pi Network Node downloaden & installieren (Silent)
   5) Windows Firewall-Ports 31400-31409 freigeben (Ein-/Ausgehend)
   6) PuTTY downloaden & installieren (winget)
   7) WireGuard Client downloaden & installieren (winget) & Schlüssel generieren
   8) WireGuard Server (Linux) automatisch konfigurieren & lokalen Tunnel einrichten
      → Statusanzeige: "(aktiv)" erscheint bei laufender Verbindung (grün hervorgehoben)
   9) PiCheck (Analysetool) downloaden, entpacken und automatisch starten
  10) Aktionen rückgängig machen / Deinstallationen:
        1) Docker Desktop entfernen
        2) Pi Network Node entfernen
        3) PuTTY entfernen
        4) WireGuard + Schlüssel entfernen
        5) Firewall-Regeln entfernen
        6) WSL2 deaktivieren
        7) PiCheck-Verzeichnis vom Desktop löschen
  11) Hilfe / Info zu allen Schritten und Kontakt zur Telegram-Gruppe
  12) Beenden des Skripts

--------------------------------------------------------------------------------
 Weitere Features:
 - Logging in pi_node_setup_log.txt (im Skriptverzeichnis)
 - Farbliche Statusanzeigen (Installiert, Aktiviert, Schlüssel vorhanden etc.)
 - Prüfung und Auswahl lokaler SSH-Keys bei Serververbindung
   → SSH-Schlüssel (OpenSSH oder .ppk) **muss im gleichen Verzeichnis liegen wie das Skript**
 - Dynamische Statusprüfung für WireGuard & Firewall
 - Unterstützung für Passwort- und Key-basierte Authentifizierung mit PuTTY
 - Temporäre Dateien werden automatisch bereinigt
 - Fehlerbehandlung mit Ausgabe und Logeinträgen
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

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    } else {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }

    $logFile = Join-Path $scriptDir "pi_node_setup_log.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp][$Level] $Message"

    Add-Content -Path $logFile -Value $logEntry

    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry -ForegroundColor Gray }
    }
}

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

    $existingPorts = @()
    foreach ($rule in $rules) {
        if ($rule.DisplayName -match '_(\d+)$') {
            $existingPorts += [int]$matches[1]
        }
    }

    # Sicherstellen, dass $existingPorts ein Array ist
    if (-not ($existingPorts -is [System.Array])) {
        $existingPorts = @($existingPorts)
    }

    $foundPorts = $requiredPorts | Where-Object { $existingPorts -contains $_ }

    # Auch $foundPorts als Array behandeln
    if (-not ($foundPorts -is [System.Array])) {
        $foundPorts = @($foundPorts)
    }

    return ($foundPorts.Count -eq $requiredPorts.Count)
}

function Is-WGConnectionActive {
    try {
        return (Get-Service | Where-Object { $_.Name -like 'WireGuardTunnel*' -and $_.Status -eq 'Running' }) -ne $null
    } catch {
        return $false
    }
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
$global:WGConnectionActive = Is-WGConnectionActive
$global:FirewallPortsOpen = Are-NodeFirewallRulesPresent
}

# === Installationsfunktionen ===

function Do-WindowsUpdates {
    Write-Log "Starte Suche nach Windows Updates..." "INFO"
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
    } catch {
        Write-Log "Fehler bei COM-Initialisierung oder Updatesuche: $_" "ERROR"
        return
    }

    $updateCount = $searchResult.Updates.Count
    Write-Log "$updateCount Updates gefunden." "INFO"

    if ($updateCount -eq 0) {
        Write-Host "Keine neuen Updates gefunden." -ForegroundColor Green
        Write-Log "Keine neuen Updates gefunden." "INFO"
        Pause
        return
    }

    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $searchResult.Updates) {
        try {
            if (-not $update.EulaAccepted) {
                $update.AcceptEula()
                Write-Log "EULA akzeptiert für: $($update.Title)"
            }
            $null = $updatesToDownload.Add($update)
            Write-Log "Update hinzugefügt zur Downloadliste: $($update.Title)"
        } catch {
            Write-Log "Fehler bei EULA oder Hinzufügen von Update '$($update.Title)': $_" "WARN"
        }
    }

    try {
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload
        $downloader.Download()
        Write-Log "Updates erfolgreich heruntergeladen." "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen der Updates: $_" "ERROR"
        return
    }

    try {
        Write-Host "Updates heruntergeladen. Installation startet …" -ForegroundColor Cyan
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToDownload
        $installationResult = $installer.Install()

        if ($installationResult.ResultCode -eq 2) {
            Write-Log "Update bereits installiert – kein weiterer Installationsbedarf." "INFO"
            Write-Host "Updates waren bereits installiert oder wurden nicht erneut angewendet." -ForegroundColor Yellow
        } else {
            Write-Log "Installations-ResultCode: $($installationResult.ResultCode)" "INFO"
            Write-Host "Installation abgeschlossen. Ergebniscode: $($installationResult.ResultCode)" -ForegroundColor Green
        }
    } catch {
        Write-Log "Fehler bei der Updateinstallation: $_" "ERROR"
    }

    Pause
}

function Do-EnableWSL2 {
    $flagPath = "$env:ProgramData\wsl2_setup_flag.txt"
    $scriptPath = $MyInvocation.MyCommand.Definition
    $autostartBatPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ResumeWSL2Setup.bat"

    if (Test-Path $flagPath) {
        Write-Host "`n Fortsetzungs-Flag erkannt – Setup wird fortgesetzt..." -ForegroundColor Cyan
        Write-Log "Fortsetzungs-Flag erkannt: $flagPath" "INFO"

        try {
            wsl --set-default-version 2
            Write-Log "WSL2 wurde als Standardversion gesetzt." "INFO"
            Write-Host "`nWSL2 wurde als Standardversion gesetzt." -ForegroundColor Green
        } catch {
            Write-Log "Fehler beim Setzen der Standardversion: $_" "ERROR"
            Write-Warning "Fehler beim Setzen der Standardversion: $_"
        }

        # Aufräumen
        Remove-Item $flagPath -Force -ErrorAction SilentlyContinue
        Remove-Item $autostartBatPath -Force -ErrorAction SilentlyContinue
        Write-Log "Fortsetzungs-Flag und Autostart-Datei entfernt." "INFO"
        Pause
        return
    }

    Write-Host "`n Prüfe WSL2-Status..." -ForegroundColor Cyan
    Write-Log "Prüfe aktuellen Status der WSL2-Komponenten..." "INFO"

    try {
        $wslEnabled = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -eq "Enabled"
        $vmEnabled  = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -eq "Enabled"
    } catch {
        Write-Log "Fehler beim Abrufen des Feature-Status: $_" "ERROR"
        return
    }

    if ($wslEnabled -and $vmEnabled) {
        Write-Host "WSL2 ist bereits vollständig aktiviert." -ForegroundColor Green
        Write-Log "WSL2 bereits vollständig aktiviert." "INFO"
        Pause
        return
    }

    Write-Host "`nAktiviere benötigte Windows-Features für WSL2..." -ForegroundColor Yellow
    Write-Log "Aktiviere Windows-Features für WSL2..." "INFO"

    try {
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -All | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All | Out-Null
        Write-Log "Windows-Features aktiviert (Subsystem + VM Platform)." "INFO"
    } catch {
        Write-Log "Fehler beim Aktivieren der Windows-Features: $_" "ERROR"
        return
    }

    try {
        Set-Content -Path $flagPath -Value "resume"
        $batContent = "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""
        Set-Content -Path $autostartBatPath -Value $batContent -Encoding ASCII
    Write-Log "Falls Autostart durch Gruppenrichtlinien blockiert ist, bitte das Skript manuell erneut ausführen." "INFO"
        Write-Log "Autostart für Fortsetzung nach Neustart eingerichtet." "INFO"
    } catch {
        Write-Log "Fehler beim Einrichten des Fortsetzungsmechanismus: $_" "ERROR"
        return
    }

    Write-Host "`nSystem wird neu gestartet – Setup wird beim nächsten Login automatisch fortgesetzt." -ForegroundColor Yellow
    Write-Log "System wird neu gestartet." "INFO"
    Pause
    Restart-Computer -Force
}


function Do-InstallWireGuard {
    Write-Host "Installiere WireGuard mit winget..." -ForegroundColor Cyan
    Write-Log "Beginne Installation von WireGuard mit winget..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }
    } catch {
        Write-Log "Winget nicht gefunden oder nicht verfügbar: $_" "ERROR"
        return
    }

    try {
        Write-Host "Starte Silent-Installation von WireGuard..." -ForegroundColor Yellow
        Write-Log "Führe winget-Installation aus: WireGuard.WireGuard" "INFO"

        winget install -e --id WireGuard.WireGuard --silent --accept-package-agreements --accept-source-agreements
        $exitCode = $LASTEXITCODE
        Write-Log "Winget-Installations-ExitCode: $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: winget-Installation meldete ExitCode $exitCode" "WARN"
        }

        Start-Process "C:\Program Files\Wireguard\Wireguard.exe" -ErrorAction Stop
        Write-Log "WireGuard erfolgreich gestartet." "INFO"
        Write-Host "WireGuard wurde erfolgreich installiert und gestartet!" -ForegroundColor Green
    } catch {
        Write-Log "Fehler bei der Installation oder dem Start von WireGuard: $_" "ERROR"
        return
    }

    try {
        $wgDir = Get-WGDir
        if ($wgDir) {
            Gen-WGKeys $wgDir
            Write-Log "WireGuard-Verzeichnis gefunden: $wgDir – Schlüssel wurden generiert." "INFO"
        } else {
            Write-Warning "WireGuard-Verzeichnis nicht gefunden."
            Write-Log "WireGuard-Verzeichnis nicht gefunden – Schlüssel wurden nicht generiert." "WARN"
        }
    } catch {
        Write-Log "Fehler beim Generieren der WireGuard-Schlüssel: $_" "ERROR"
    }

    Pause
}

function Do-FirewallPorts {
    Write-Host 'Setze Firewall-Regeln für Ports 31400-31409 …' -ForegroundColor Cyan
    Write-Log "Beginne mit dem Erstellen von Firewallregeln für Ports 31400–31409..." "INFO"

    foreach ($p in 31400..31409) {
        try {
            New-NetFirewallRule -DisplayName "PiNode_TCP_In_$p"  -Direction Inbound  -Protocol TCP -LocalPort $p -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName "PiNode_TCP_Out_$p" -Direction Outbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            Write-Log "Firewallregeln für Port $p erfolgreich erstellt." "INFO"
        } catch {
            Write-Warning "Fehler beim Erstellen der Firewallregel für Port ${p}: $_"
        Write-Log "Fehler beim Erstellen der Firewallregel für Port ${p}: $_" "ERROR"
        }
    }

    Write-Host 'Firewall-Regeln erstellt.' -ForegroundColor Green
    Write-Log "Alle Firewall-Regeln wurden abgearbeitet." "INFO"
    Pause
}

function Do-InstallPuTTY {
    Write-Host 'Installiere PuTTY...' -ForegroundColor Cyan
    Write-Log "Beginne Installation von PuTTY mit winget..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte sicherstellen, dass es installiert ist."
        }

        $process = Start-Process 'winget' -ArgumentList 'install', '--id', 'PuTTY.PuTTY', '-e', '--accept-source-agreements', '--accept-package-agreements' -Wait -PassThru
        $exitCode = $process.ExitCode
        Write-Log "PuTTY-Installation abgeschlossen mit ExitCode $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: PuTTY winget-Installation meldete ExitCode $exitCode" "WARN"
        }
    } catch {
        Write-Log "Fehler bei der Installation von PuTTY: $_" "ERROR"
    }

    Pause
}

function Do-InstallDocker {
    Write-Host "Installiere Docker Desktop.." -ForegroundColor Cyan
    Write-Log "Starte Installation von Docker Desktop..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }

        Write-Host "Starte Silent-Installation von Docker Desktop..." -ForegroundColor Yellow
        Write-Log "Führe winget-Installation aus: Docker.DockerDesktop" "INFO"
        winget install -e --id Docker.DockerDesktop --silent --accept-package-agreements --accept-source-agreements
        $exitCode = $LASTEXITCODE
        Write-Log "Docker winget-Installations-ExitCode: $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: winget meldete ExitCode $exitCode" "WARN"
        }

        Start-Sleep -Seconds 5

        Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction Stop
        Write-Host "Docker Desktop wurde erfolgreich installiert und gestartet!" -ForegroundColor Green
        Write-Log "Docker Desktop erfolgreich gestartet." "INFO"
    }
    catch {
        Write-Host "FEHLER: $_" -ForegroundColor Red
        Write-Host "Tipp: Stellen Sie sicher, dass winget verfügbar und aktuell ist." -ForegroundColor Yellow
        Write-Log "Fehler bei der Docker-Installation: $_" "ERROR"
    }

    Pause
}

function Do-InstallPiNode {
    Write-Host "Installiere Pi Network Node Software..." -ForegroundColor Cyan
    Write-Log "Beginne Installation der Pi Network Node Software..." "INFO"

    $url = "https://downloads.minepi.com/Pi%20Network%20Setup%200.5.0.exe"
    $installerPath = "$env:TEMP\PiNetworkSetup050.exe"

    try {
        & curl.exe -L $url -o $installerPath
        $exitCode = $LASTEXITCODE
        Write-Log "curl.exe Download abgeschlossen mit ExitCode $exitCode" "INFO"

        if ($exitCode -ne 0 -or -not (Test-Path $installerPath)) {
            throw "Download fehlgeschlagen oder Datei nicht vorhanden."
        }
        Write-Log "Pi Node Installer erfolgreich heruntergeladen: $installerPath" "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen des Installers: $_" "ERROR"
        return
    }

    try {
        Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait -ErrorAction Stop
        Write-Log "Installer wurde erfolgreich im Silent-Modus ausgeführt." "INFO"
        Write-Host "Pi Network Node erfolgreich installiert und gestartet!" -ForegroundColor Green
    } catch {
        Write-Log "Fehler beim Starten des Installers: $_" "ERROR"
    }

    Pause
}


function DownloadAndStartPiCheck {
    Write-Host 'Lade PiCheck-Archiv mit curl herunter ...' -ForegroundColor Cyan
    Write-Log "Starte Download von PiCheck-Archiv..." "INFO"

    $url = "https://github.com/muratyurdakul75/picheck/archive/refs/heads/main.zip"
    $tempPath = "$env:TEMP"
    $zipPath = Join-Path $tempPath "picheck-main.zip"
    $unzipPath = Join-Path $tempPath "picheck-unpacked"
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $targetPath = Join-Path $desktopPath "PiCheck"

    try {
        if (Test-Path $unzipPath) { Remove-Item -Path $unzipPath -Recurse -Force -ErrorAction Stop }
        if (Test-Path $targetPath) { Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop }

        if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            throw "curl.exe wurde nicht gefunden."
        }

        $curlCmd = "curl.exe -L -o `"$zipPath`" `"$url`""
        cmd.exe /c $curlCmd

        if (-not (Test-Path $zipPath)) {
            throw "ZIP-Datei wurde nicht erstellt. Download fehlgeschlagen."
        }

        Write-Host "Entpacke Hauptarchiv ..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $unzipPath -Force
        Write-Log "Archiv erfolgreich entpackt: $zipPath → $unzipPath" "INFO"

        $versionZips = Get-ChildItem -Path $unzipPath -Recurse -Filter "*.zip" | ForEach-Object {
            if ($_.Name -match '(\d+\.\d+\.\d+)') {
                [PSCustomObject]@{ File = $_; Version = [version]$matches[1] }
            }
        }

        if (-not $versionZips) {
            throw "Keine gültigen PiCheck-Versionen gefunden."
        }

        $latest = $versionZips | Sort-Object Version -Descending | Select-Object -First 1
        Write-Log "PiCheck-Version gefunden: $($latest.Version) – $($latest.File.FullName)" "INFO"

        Expand-Archive -Path $latest.File.FullName -DestinationPath $targetPath -Force

        $exePath = Get-ChildItem -Path $targetPath -Filter "picheck.exe" -Recurse | Select-Object -First 1
        if (-not $exePath) {
            throw "picheck.exe wurde nicht gefunden im Zielverzeichnis."
        }

        $vcInstaller = Get-ChildItem -Path $targetPath -Filter "VC_redist.x64.exe" -Recurse | Select-Object -First 1
        if ($vcInstaller) {
            Write-Host "Installiere VC_redist.x64.exe im Silent-Mode ..." -ForegroundColor Cyan
            Start-Process -FilePath $vcInstaller.FullName -ArgumentList "/quiet", "/norestart" -Wait
            Write-Log "VC_redist.x64.exe wurde ausgeführt." "INFO"
        } else {
            Write-Log "VC_redist.x64.exe nicht gefunden – wird übersprungen." "WARN"
        }

        Write-Host "Starte picheck.exe /auto ..." -ForegroundColor Green
        Start-Process -FilePath $exePath.FullName -ArgumentList "/auto"
        Write-Log "picheck.exe gestartet mit Argument /auto." "INFO"

        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $unzipPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Temporäre Dateien entfernt." "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen oder Ausführen von PiCheck: $_" "ERROR"
    }
    Write-Host "Zurück zum Hauptmenü..." -ForegroundColor Gray
    Pause
}

# Uninstall-Menü
function Show-UninstallMenu {
    Clear-Host
    Write-Host '===[ Rückgängig machen / Deaktivieren ]===' -ForegroundColor Red
    Write-Host ''
    Write-Host '0) Alles entfernen (komplett)' -ForegroundColor DarkRed
    Write-Host '1) Deinstalliere Docker Desktop'
    Write-Host '2) Entferne Pi Network Node'
    Write-Host '3) Entferne PuTTY'
    Write-Host '4) Entferne WireGuard + Schlüssel'
    Write-Host '5) Entferne Firewall-Regeln (31400–31409)'
    Write-Host '6) Deaktiviere WSL2'
    Write-Host '7) Entferne PiCheck-Verzeichnis vom Desktop'
    Write-Host '8) Zurück zum Hauptmenü'
    Write-Host ''
}

function Undo-Docker {
    $confirm = Read-Host "Bist du sicher, dass du Docker Desktop entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-Docker abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Beende Docker-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Deinstalliere Docker Desktop..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von Docker Desktop..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "Docker.DockerDesktop", "-e", "--silent" -Wait
        Write-Log "Docker Desktop wurde deinstalliert." "INFO"
    } catch {
        Write-Log "Fehler bei Docker-Deinstallation: $_" "ERROR"
    }
    Pause
}

function Undo-PiNode {
    $confirm = Read-Host "Bist du sicher, dass du Pi Network Node entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PiNode abgebrochen." "INFO"
        Pause
        return
    }

    Write-Host "Beende Pi Node-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "pi-network-desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $path = "$env:LOCALAPPDATA\Programs\pi-network-desktop"
    Write-Host "Entferne Pi Network Node..." -ForegroundColor Cyan
    Write-Log "Beginne Entfernung von Pi Network Node..." "INFO"

    try {
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force -ErrorAction Stop
            Write-Log "Pi Network Node wurde entfernt." "INFO"
        } else {
            Write-Log "Pi Network Node-Verzeichnis nicht gefunden: $path – vermutlich bereits entfernt." "WARN"
            Write-Host "Verzeichnis nicht vorhanden – vermutlich bereits gelöscht." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Fehler beim Entfernen des Pi Node: $_" "ERROR"
    }

    Pause
}


function Undo-PuTTY {
    $confirm = Read-Host "Bist du sicher, dass du PuTTY entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PuTTY abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Beende PuTTY-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "putty" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Deinstalliere PuTTY..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von PuTTY..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "PuTTY.PuTTY", "-e", "--silent" -Wait
        Write-Log "PuTTY wurde deinstalliert." "INFO"
    } catch {
        Write-Log "Fehler bei PuTTY-Deinstallation: $_" "ERROR"
    }
    Pause
}

function Undo-WireGuard {
    $confirm = Read-Host "Bist du sicher, dass du WireGuard entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-WireGuard abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Beende WireGuard-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "wireguard" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Deinstalliere WireGuard und entferne Schlüssel..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von WireGuard..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "WireGuard.WireGuard", "-e", "--silent" -Wait
        Write-Log "WireGuard wurde deinstalliert." "INFO"
        $wg = Get-WGDir
        if ($wg) {
            Remove-Item -Path (Join-Path $wg 'keys') -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "WireGuard-Schlüsselverzeichnis entfernt." "INFO"
        }
    } catch {
        Write-Log "Fehler bei WireGuard-Deinstallation: $_" "ERROR"
    }
    Pause
}

function Undo-FirewallRules {
    $confirm = Read-Host "Bist du sicher, dass du die Firewall-Regeln entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-FirewallRules abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Entferne Firewall-Regeln für Ports 31400–31409..." -ForegroundColor Cyan
    Write-Log "Beginne Entfernung von Firewallregeln..." "INFO"
    foreach ($p in 31400..31409) {
        Remove-NetFirewallRule -DisplayName "PiNode_TCP_In_$p" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "PiNode_TCP_Out_$p" -ErrorAction SilentlyContinue
    }
    Write-Log "Firewallregeln entfernt." "INFO"
    Pause
}

function Undo-WSL2 {
    $confirm = Read-Host "Bist du sicher, dass du WSL2 deaktivieren möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-WSL2 abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Deaktiviere WSL2-Funktionalität..." -ForegroundColor Cyan
    Write-Log "Beginne Deaktivierung von WSL2..." "INFO"
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop
        Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
        Write-Log "WSL2 wurde deaktiviert." "INFO"
    } catch {
        Write-Log "Fehler bei der WSL2-Deaktivierung: $_" "ERROR"
    }
    Pause
}

function Undo-All {
    $confirm = Read-Host "Bist du sicher, dass du ALLE Komponenten entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-All abgebrochen." "INFO"
        Pause
        return
    }

    Undo-PiCheck
    Undo-WireGuard
    Undo-Docker
    Undo-PuTTY
    Undo-PiNode
    Undo-FirewallRules
    Undo-WSL2

    Write-Host "Alle Komponenten wurden entfernt (soweit möglich)." -ForegroundColor Green
    Write-Log "Alle Komponenten wurden im Rahmen von Undo-All entfernt." "INFO"
    Pause
}

function Undo-PiCheck {
    $confirm = Read-Host "Bist du sicher, dass du das PiCheck-Verzeichnis entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PiCheck abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Entferne PiCheck-Verzeichnis vom Desktop..." -ForegroundColor Cyan
    Write-Log "Entferne PiCheck-Verzeichnis vom Desktop..." "INFO"
    try {
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $targetPath = Join-Path $desktopPath "PiCheck"
        if (Test-Path $targetPath) {
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
            Write-Log "PiCheck-Verzeichnis wurde entfernt: $targetPath" "INFO"
        } else {
            Write-Log "PiCheck-Verzeichnis war nicht vorhanden: $targetPath" "INFO"
        }
    } catch {
        Write-Log "Fehler beim Entfernen des PiCheck-Verzeichnisses: $_" "ERROR"
    }
    Pause
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
    if (-not $pu) {
        Write-Warning "PuTTY nicht gefunden."
        Write-Log "PuTTY nicht gefunden für HostKey-Akzeptanz." "ERROR"
        return
    }

    Remove-AllHostKeysForIP -serverIp $serverIp
    $plink = Join-Path $pu 'plink.exe'
    if (-not (Test-Path $plink)) {
        Write-Log "plink.exe nicht gefunden im Pfad $plink" "ERROR"
        return
    }

    Write-Host "Akzeptiere SSH-Hostkey von $serverIp automatisch..." -ForegroundColor Yellow
    Write-Log "Beginne mit automatischer SSH-Hostkey-Akzeptanz für $serverIp" "INFO"

    try {
        $responseFile = [System.IO.Path]::GetTempFileName()
        "y`n" | Out-File -FilePath $responseFile -Encoding ASCII
    } catch {
        Write-Log "Fehler beim Erstellen der temporären Antwortdatei: $_" "ERROR"
        return
    }

    $args = @()
    if ($password) {
        $args += "-pw", $password
    } elseif ($privateKeyPath) {
        $args += "-i", "`"$privateKeyPath`""
    }

    $args += "-batch", "-no-antispoof", "-T"
    $args += "$user@$serverIp", "exit"

    try {
        $process = Start-Process -FilePath $plink -ArgumentList $args -Wait -NoNewWindow -RedirectStandardInput $responseFile -PassThru
        $exitCode = $process.ExitCode
        Write-Log "plink.exe ausgeführt mit ExitCode $exitCode" "INFO"
        if ($exitCode -ne 0) {
            Write-Log "Fehler beim Akzeptieren des Hostkeys (ExitCode $exitCode)" "WARN"
        }
    } catch {
        Write-Log "Fehler beim Starten von plink.exe: $_" "ERROR"
    } finally {
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        Write-Log "Temporäre Antwortdatei entfernt." "INFO"
    }
}

function Convert-OpenSSHKeyToPPK {
    param (
        [string]$opensshKeyPath,
        [string]$puttygenPath,
        [string]$ppkOutPath
    )

    Write-Log "Starte Konvertierung von OpenSSH-Key nach PPK..." "INFO"
    Write-Log "Eingabe: $opensshKeyPath | Ziel: $ppkOutPath" "INFO"

    if (-not (Test-Path $puttygenPath)) {
        Write-Error "puttygen.exe nicht gefunden. Bitte sicherstellen, dass PuTTY installiert ist."
        Write-Log "Fehlender puttygen.exe Pfad: $puttygenPath" "ERROR"
        return $null
    }

    if (-not (Test-Path $opensshKeyPath)) {
        Write-Error "OpenSSH-Schlüssel nicht gefunden: $opensshKeyPath"
        Write-Log "OpenSSH-Key fehlt: $opensshKeyPath" "ERROR"
        return $null
    }

    try {
        Write-Host "Konvertiere OpenSSH-Key nach PuTTY-Format (.ppk)..." -ForegroundColor Cyan
        & $puttygenPath "`"$opensshKeyPath`"" -o "`"$ppkOutPath`"" | Out-Null

        if (Test-Path $ppkOutPath) {
            Write-Host "Konvertierung erfolgreich: $ppkOutPath" -ForegroundColor Green
            Write-Log "Konvertierung erfolgreich abgeschlossen: $ppkOutPath" "INFO"
            return $ppkOutPath
        } else {
            throw "PPK-Datei wurde nicht erstellt."
        }
    } catch {
        Write-Error "Konvertierung fehlgeschlagen: $_"
        Write-Log "Fehler bei der Konvertierung zu PPK: $_" "ERROR"
        return $null
    }
}

# === WireGuard-Keys generieren ===
function Gen-WGKeys($dir) {
    $keyDir = Join-Path $dir 'keys'
    if (-not (Test-Path $keyDir)) {
        try {
            New-Item -Path $keyDir -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Log "Key-Verzeichnis erstellt: $keyDir" "INFO"
        } catch {
            Write-Log "Fehler beim Erstellen des Key-Verzeichnisses: $_" "ERROR"
            return
        }
    }

    $wgExe = Join-Path $dir 'wg.exe'
    if (-not (Test-Path $wgExe)) {
        Write-Log "wg.exe nicht gefunden im Pfad $wgExe" "ERROR"
        return
    }

    try {
        $priv = & $wgExe genkey
        if ([string]::IsNullOrWhiteSpace($priv)) {
            throw "Private Key konnte nicht generiert werden."
        }

        $pub = $priv | & $wgExe pubkey
        if ([string]::IsNullOrWhiteSpace($pub)) {
            throw "Public Key konnte nicht generiert werden."
        }

        $privPath = Join-Path $keyDir 'wg_private.key'
        $pubPath  = Join-Path $keyDir 'wg_public.key'

if (Test-Path $privPath -or Test-Path $pubPath) {
    $overwrite = Read-Host "Schlüssel existieren bereits. Überschreiben? (J/N)"
    if ($overwrite -notmatch '^[Jj]$') {
        Write-Log "Abbruch: Benutzer will vorhandene Schlüssel nicht überschreiben." "WARN"
        return
    }
}


        $priv | Out-File $privPath -Encoding ASCII
        $pub  | Out-File $pubPath  -Encoding ASCII

        Write-Log "WireGuard-Schlüssel erfolgreich erstellt: $privPath & $pubPath" "INFO"
    } catch {
        Write-Log "Fehler bei der WireGuard-Keygenerierung: $_" "ERROR"
    }
}

# === WireGuard-Server-Setup komplett ===
function Do-SetupWGServer {
    $wg = Get-WGDir
    $pu = Get-PuTTYDir
    if (-not $pu) { Write-Warning 'PuTTY nicht installiert.'; Write-Log 'PuTTY nicht installiert.' 'ERROR'; return }
    if (-not $wg) { Write-Warning 'WireGuard nicht installiert.'; Write-Log 'WireGuard nicht installiert.' 'ERROR'; return }

    $serverIp = Read-Host 'IPv4 Adresse des vServers'
    Write-Log "Server-IP eingegeben: $serverIp" 'INFO'

    $authChoice = Read-Host 'Authentifizierungsmethode? (pw für Passwort / key für SSH-Key)'
    $plinkAuthArgs = @()

    if ($authChoice -eq 'pw') {
        $cred = Read-Host 'Root-Passwort' -AsSecureString
        $pwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))
        Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -password $pwd
        $plinkAuthArgs += '-pw', $pwd
    }
    elseif ($authChoice -eq 'key') {
        $scriptDir = if ($PSCommandPath) {
            Split-Path -Parent $PSCommandPath
        } else {
            Split-Path -Parent $MyInvocation.MyCommand.Definition
        }

        $keyFiles = Get-ChildItem -Path $scriptDir -File | Where-Object {
            $_.Extension -in ".key", "" -and -not $_.Name.EndsWith(".ppk")
        }

        if ($keyFiles.Count -eq 0) {
            Write-Error "Keine geeigneten SSH-Key-Dateien im Skriptverzeichnis gefunden."
            Write-Log "Keine SSH-Keys gefunden im Verzeichnis $scriptDir" "ERROR"
            return
        }

        Write-Host "`nVerfügbare SSH-Key-Dateien:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $keyFiles.Count; $i++) {
            Write-Host "$i`t$keyFiles[$i].Name"
        }
        [int]$sel = Read-Host "`nBitte Nummer der gewünschten Key-Datei eingeben"
        if ($sel -lt 0 -or $sel -ge $keyFiles.Count) {
            Write-Error "Ungültige Auswahl."
            Write-Log "Benutzer wählte ungültigen Index $sel bei Key-Auswahl." "WARN"
            return
        }

        $opensshKey = $keyFiles[$sel].FullName
        $ppkKey     = [System.IO.Path]::ChangeExtension($opensshKey, ".ppk")
        $ppkWasTemporary = $false

        if (-not (Test-Path $ppkKey)) {
            $puttygen = Join-Path $pu 'puttygen.exe'
            if (-not (Test-Path $puttygen)) {
                Write-Error "puttygen.exe nicht gefunden: $puttygen"
                Write-Log "puttygen.exe nicht gefunden für Konvertierung" "ERROR"
                return
            }
            $convertedKey = Convert-OpenSSHKeyToPPK -opensshKeyPath $opensshKey -puttygenPath $puttygen -ppkOutPath $ppkKey
            if (-not $convertedKey) { return }
            $ppkWasTemporary = $true
        }

        Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -privateKeyPath $ppkKey
        $plinkAuthArgs += '-i', $ppkKey

        if ($ppkWasTemporary) {
            Cleanup-TemporaryFiles -ppkPath $ppkKey
        }
    } else {
        Write-Error "Ungültige Auswahl. Bitte 'pw' oder 'key' eingeben."
        Write-Log "Ungültige Authentifizierungsmethode: $authChoice" 'WARN'
        return
    }

    $wgExe = Join-Path $wg 'wg.exe'
    $keyDir = Join-Path $wg 'keys'
    $clientPrivPath = Join-Path $keyDir 'wg_private.key'
    $clientPubPath  = Join-Path $keyDir 'wg_public.key'

    if (-not (Test-Path $clientPrivPath) -or -not (Test-Path $clientPubPath)) {
        Write-Log "Client-Keys nicht gefunden: $clientPrivPath oder $clientPubPath fehlen." 'ERROR'
        return
    }

    $clientPriv = Get-Content $clientPrivPath -Raw
    $clientPub  = Get-Content $clientPubPath -Raw

    $serverPriv = & $wgExe genkey
    $serverPub  = $serverPriv | & $wgExe pubkey

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
    $plink = Join-Path $pu 'plink.exe'

    if ($authChoice -eq 'pw') {
        & $pscp -batch -pw $pwd $tempScript "root@${serverIp}:/tmp/wg_setup.sh"
        & $plink -batch -pw $pwd "root@${serverIp}" "bash /tmp/wg_setup.sh"
    }
    elseif ($authChoice -eq 'key') {
        & $pscp -batch -i "`"$ppkKey`"" $tempScript "root@${serverIp}:/tmp/wg_setup.sh"
        & $plink -batch -i "`"$ppkKey`"" "root@${serverIp}" "bash /tmp/wg_setup.sh"
    }

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

  Write-Host '8) Automatisch WireGuard Server einrichten & Client verbinden ' -ForegroundColor Yellow -NoNewline
if ($WGConnectionActive) {
    Write-Host '(' -ForegroundColor Yellow -NoNewline
    Write-Host 'aktiv' -ForegroundColor Green -NoNewline
    Write-Host ')' -ForegroundColor Yellow
} else {
    Write-Host ''
}

    # === Gruppe 9: Analyse-Tool ===
    Write-Host '9) PiCheck herunterladen, entpacken und starten' -ForegroundColor White

Write-Host '10) Aktionen rückgängig machen (Uninstall/Deaktivieren)' -ForegroundColor DarkRed


    # === Gruppe 11–12: Info & Exit ===
    Write-Host '11) Hilfe / Info' -ForegroundColor DarkGreen
    Write-Host '12) Beenden' -ForegroundColor DarkGreen

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
        '9'  { DownloadAndStartPiCheck }
        '10' {
    $runningUninstallMenu = $true
    while ($runningUninstallMenu) {
        Show-UninstallMenu
        $undoChoice = Read-Host 'Auswahl'
        switch ($undoChoice) {
            '0' { Undo-All }
            '1' { Undo-Docker }
            '2' { Undo-PiNode }
            '3' { Undo-PuTTY }
            '4' { Undo-WireGuard }
            '5' { Undo-FirewallRules }
            '6' { Undo-WSL2 }
            '7' { Undo-PiCheck }
            '8' { $runningUninstallMenu = $false }
            default { Write-Warning 'Ungültige Eingabe'; Pause }
        }
    }
}
'11' {
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
'12' {
    Write-Log "Setup durch Benutzer beendet." 'INFO'
    Write-Host 'Setup beendet.'
    exit
}

        default {
            Write-Warning 'Ungültige Auswahl'
            Pause
        }
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

