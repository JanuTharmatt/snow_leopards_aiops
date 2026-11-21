# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Spec File for Privacy-First AIOps Collector Control Center.
Produces a standalone single-file Windows executable: collector.exe
Bundles:
- CustomTkinter themes, fonts, and assets
- Pystray system tray libraries
- SQLite, psutil, ping3, requests, pydantic
Runs without requiring a local Python installation on the target Windows host.
"""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect CustomTkinter assets (themes, fonts, shapes)
datas = collect_data_files('customtkinter')

# Hidden imports required by dynamic GUI modules
hiddenimports = [
    'customtkinter',
    'pystray',
    'PIL',
    'PIL._tkinter_finder',
    'darkdetect',
    'psutil',
    'ping3',
    'requests',
    'pydantic',
    'regex',
    'sqlite3',
    'winreg',
]
hiddenimports += collect_submodules('customtkinter')

a = Analysis(
    ['run_ui.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='collector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windowed GUI application (no black terminal popup)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
