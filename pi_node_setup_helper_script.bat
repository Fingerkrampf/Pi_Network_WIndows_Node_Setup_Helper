:: Dieses Skript ist freie Software: Sie können es unter den Bedingungen
:: der GNU General Public License, Version 3 oder jeder späteren Version, weiterverbreiten und/oder modifizieren.
:: Siehe <https://www.gnu.org/licenses/>.

@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0pi_node_setup_helper_script.ps1" %*
pause
