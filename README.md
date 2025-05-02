# Pi Network Windows Node Setup Helper

Dieses Projekt enthält ein PowerShell-Skript, das den automatisierten Download, die Installation, Konfiguration und den Start eines Pi Network Nodes auf Windows-Systemen ermöglicht. Zusätzlich wird ein WireGuard-Tunnel über einen gemieteten vServer eingerichtet, um den Node über eine IPv4-Adresse erreichbar zu machen.

## Features
- Automatischer Download und Installation des Pi Network Nodes und weiteren benötigten Programmen
- Konfiguration des Nodes mit entsprechenden Programmen und Befehlen
- Einrichtung eines WireGuard-Tunnels, um den Node über IPv4 zu erreichen
- Unterstützung für Windows PowerShell 5.x

## Voraussetzungen
- Windows 10/11 oder Windows Server (mit PowerShell 5.x)
- Administratorrechte auf dem Computer
- Ein vServer, der über eine eigene IPv4 Adresse verfügt.

## Installation und Nutzung

1. Klone das Repository:
   ```bash
   git clone https://github.com/Fingerkrampf/Pi_Network_WIndows_Node_Setup_Helper.git

2. Navigiere in das Verzeichnis des geklonten Projekts:
    ```bash
   cd Pi_Network_WIndows_Node_Setup_Helper
   
4. Starte das Skript über die Batch-Datei:
    ```bash
   .\start.bat

Lizenz

Dieses Projekt steht unter der GNU General Public License v3.0 – siehe die Datei LICENSE für Details.
Hinweis
    Du musst möglicherweise Anpassungen im Skript vornehmen, um sicherzustellen, dass deine spezifischen Anforderungen und der vServer korrekt eingerichtet sind.
    Es wird empfohlen, dass du das Skript zunächst in einer Testumgebung ausprobierst, um sicherzustellen, dass alles wie erwartet funktioniert.

   ## Kontakt
Bei Fragen oder Anmerkungen kannst du uns/mich (Fingerkrampf) über unsere Telegram-Gruppe erreichen: [Pi Netzwerk Deutschland](https://t.me/pinetzwerkdeutschland).
