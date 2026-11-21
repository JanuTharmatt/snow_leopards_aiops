"""
Windows Auto-Start Manager.
Manages the 'Start With Windows' feature using the Windows Registry:
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
Allows the Collector Control Center / Collector Service to start automatically on system boot.
"""

import os
from pathlib import Path
import sys

APP_NAME = "PrivacyAIOpsCollector"
RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


class WindowsAutoStartManager:
    """Manages Windows startup registry entries."""

    @staticmethod
    def _is_windows() -> bool:
        return sys.platform == "win32"

    def is_autostart_enabled(self) -> bool:
        """Checks if startup entry exists in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."""
        if not self._is_windows():
            return False

        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
                winreg.QueryValueEx(key, APP_NAME)
                return True
        except (FileNotFoundError, OSError):
            return False

    def enable_autostart(self, custom_command: str = None) -> bool:
        """
        Registers executable or python script into Windows Startup.
        """
        if not self._is_windows():
            return False

        try:
            import winreg
            if custom_command:
                command = custom_command
            elif getattr(sys, "frozen", False):
                # When packaged as collector.exe via PyInstaller
                command = f'"{sys.executable}"'
            else:
                # When running as python script
                run_script = Path(__file__).resolve().parent.parent / "run_ui.py"
                command = f'"{sys.executable}" "{run_script}" --minimized'

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
            return True
        except Exception:
            return False

    def disable_autostart(self) -> bool:
        """Removes the application from Windows Startup."""
        if not self._is_windows():
            return False

        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, APP_NAME)
            return True
        except (FileNotFoundError, OSError):
            return True  # Already disabled
        except Exception:
            return False


autostart_manager = WindowsAutoStartManager()
