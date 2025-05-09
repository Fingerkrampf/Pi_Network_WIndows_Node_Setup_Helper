# Pi Network Windows Node Setup Helper

Dieses Projekt enthält ein PowerShell-Skript, das den vollautomatisierten Download, die Installation, Konfiguration und Aktivierung eines Pi Network Nodes auf Windows-Systemen übernimmt. Zusätzlich wird ein WireGuard-Tunnel zu einem gemieteten Linux-vServer eingerichtet, um den Node über eine öffentliche IPv4-Adresse erreichbar zu machen – ideal bei reinem IPv6-Zugang zuhause.

## ⚙️ Features

- Vollständiges Setup-Menü mit Schritt-für-Schritt Steuerung
- Automatische Statusanzeige (Installiert / Aktiviert)
- Installation aller benötigten Tools:  
  `WSL2`, `Docker Desktop`, `WireGuard`, `PuTTY`, `Pi Node`
- WireGuard-Tunnel-Setup mit automatischer Konfiguration auf Windows-Client und Linux-Server
- Passwort- und SSH-Key-basierte Authentifizierung möglich
- Keine PowerShell Core erforderlich – 100 % kompatibel mit PowerShell 5.1

## 🧰 Voraussetzungen

- Windows 10 / 11 mit PowerShell 5.x
- Administratorrechte
- Root-Zugang zu einem gemieteten vServer mit Ubuntu/Debian und öffentlicher IPv4
- SSH-Key oder Root-Passwort
- Funktionierende Internetverbindung

## 🚀 Installation und Nutzung

```bash
git clone https://github.com/Fingerkrampf/Pi_Network_WIndows_Node_Setup_Helper.git
cd Pi_Network_WIndows_Node_Setup_Helper
.\start.bat
```

## 🔐 Hinweis zu SSH-Keys

Wenn du dich per Key beim vServer anmelden möchtest, muss sich der private OpenSSH-Key im gleichen Verzeichnis wie das Skript befinden. Der Key kann automatisch ins .ppk-Format für PuTTY konvertiert werden.

## 📝 Lizenz

Dieses Projekt steht unter der [GNU General Public License v3.0](https://www.gnu.org/licenses/).

## ⚠️ Hinweis zur Anpassung

Passe das Skript ggf. an deine Umgebung an (z. B. vServer-IP, SSH-Zugänge, vorhandene Software). Nutze zum Testen vorzugsweise eine VM oder Testumgebung.

## 📞 Kontakt

👉 Telegram-Gruppe: **[Pi Netzwerk Deutschland](https://t.me/pinetzwerk_deutschland)**  
2025 – by **Fingerkrampf / PiNetzwerkDeutschland.de**
