# Pi Network Windows Node Setup Helper

Dieses Projekt enthält ein PowerShell-Skript, das den **vollautomatisierten Download, die Installation, Konfiguration und Aktivierung eines Pi Network Nodes auf Windows-Systemen** übernimmt. Zusätzlich wird ein WireGuard-Tunnel zu einem gemieteten Linux-vServer eingerichtet, um den Node über eine öffentliche IPv4-Adresse erreichbar zu machen – ideal bei reinem IPv6-Zugang zuhause.

---

## ⚙️ Features

- Komplettmenü für jeden Setup-Schritt
- Automatische Statusanzeige (Installiert / Aktiviert / Konfiguriert)
- Installation aller benötigten Tools (WSL2, Docker, WireGuard, PuTTY, Pi Node)
- Einrichtung & Aktivierung eines WireGuard-Tunnels (Client & Linux-Server automatisiert)
- Logging aller Aktionen und Fehler in `pi_node_setup_log.txt`
- Unterstützung für Passwort- & SSH-Key-basierte Authentifizierung
- Rückgängig-Funktionen (Deinstallationen, Cleanup)
- Anzeige aktiver WireGuard-Verbindung im Menü
- Unterstützung für PowerShell 5.x (kein PowerShell Core erforderlich)

---

## 🧰 Voraussetzungen

- Windows 10 / 11 oder Windows Server mit **PowerShell 5.x**
- **Administratorrechte**
- **Ein gemieteter vServer** (Root-Zugang, Ubuntu/Debian-basiert, öffentliche IPv4)
- **SSH-Key oder Root-Passwort**
- Eine funktionierende Internetverbindung

---

## 🚀 Installation und Nutzung

1. Repository klonen:
   ```bash
   git clone https://github.com/Fingerkrampf/Pi_Network_WIndows_Node_Setup_Helper.git
   ```

2. Ins Projektverzeichnis wechseln:
   ```bash
   cd Pi_Network_WIndows_Node_Setup_Helper
   ```

3. Skript über die Batch-Datei starten:
   ```bash
   .\start.bat
   ```

---

## 🔐 Hinweis zu SSH-Keys

Wenn du dich per Key beim vServer anmelden möchtest, **muss sich der private OpenSSH-Key im gleichen Verzeichnis wie das Skript befinden**. Der Schlüssel kann automatisch ins `.ppk`-Format konvertiert werden.

---

## 📝 Lizenz

Dieses Projekt steht unter der **GNU General Public License v3.0**.  
Siehe die Datei `LICENSE` für Details.

---

## ⚠️ Hinweis zur Anpassung

Du solltest das Skript ggf. an deine Umgebung anpassen (z. B. verwendeter vServer, bestehende Software). Teste das Skript idealerweise zuerst in einer VM oder Testumgebung.

---

## 📞 Kontakt

Bei Fragen oder Anregungen:
👉 [Telegram-Gruppe: Pi Netzwerk Deutschland](https://t.me/pinetzwerkdeutschland)

---

2025 – by Fingerkrampf / PiNetzwerkDeutschland.de
