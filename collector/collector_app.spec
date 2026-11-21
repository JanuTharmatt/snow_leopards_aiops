# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Spec File for Privacy-First AIOps Collector Control Center.
Produces a standalone single-file Windows executable: collector.exe

Bundles:
- Complete ui package (ui.app, ui.service_controller, ui.state_manager, ui.tray, ui.autostart)
- Complete collector package (collector.collector, config, auth_client, buffer_manager, egress_worker, heartbeat_service)
- CustomTkinter themes, fonts, and assets
- Pystray system tray libraries
- psutil, ping3, requests, pydantic, regex, sqlite3
Guarantees execution on clean Windows installations without Python installed.
"""

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Base directories
SPEC_DIR = Path(SPECPATH).resolve() if 'SPECPATH' in locals() else Path(__file__).resolve().parent
ROOT_DIR = SPEC_DIR.parent if SPEC_DIR.name == "collector" else SPEC_DIR
COLLECTOR_DIR = ROOT_DIR / "collector"

# Collect CustomTkinter assets (themes, fonts, shapes)
datas = collect_data_files('customtkinter')
datas += collect_data_files('PIL')
datas += [
    (str(COLLECTOR_DIR / 'ui'), 'ui'),
    (str(COLLECTOR_DIR / 'ui'), 'collector/ui'),
    (str(COLLECTOR_DIR), 'collector'),
]

# Hidden imports required by dynamic GUI modules & background daemon
hiddenimports = [
    'ui',
    'ui.app',
    'ui.service_controller',
    'ui.state_manager',
    'ui.autostart',
    'ui.tray',
    'collector',
    'collector.collector',
    'collector.config',
    'collector.auth_client',
    'collector.payload_builder',
    'collector.buffer_manager',
    'collector.egress_worker',
    'collector.heartbeat_service',
    'collector.models',
    'collector.security_pipeline',
    'collector.metadata_engine',
    'collector.ui',
    'collector.ui.app',
    'collector.ui.service_controller',
    'collector.ui.state_manager',
    'collector.ui.autostart',
    'collector.ui.tray',
    'customtkinter',
    'pystray',
    'pystray._win32',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'PIL._tkinter_finder',
    'darkdetect',
    'six',
    'psutil',
    'ping3',
    'requests',
    'pydantic',
    'regex',
    'sqlite3',
    'winreg',
    'socket',
    'uuid',
    'hashlib',
    'hmac',
    'json',
    'urllib',
    'urllib.parse',
    'threading',
    'logging',
    'argparse',
]

hiddenimports += collect_submodules('customtkinter')
hiddenimports += collect_submodules('pystray')
hiddenimports += collect_submodules('PIL')
hiddenimports += collect_submodules('collector')
hiddenimports += collect_submodules('ui')

entrypoint = str(ROOT_DIR / 'run_ui.py')

a = Analysis(
    [entrypoint],
    pathex=[str(ROOT_DIR), str(COLLECTOR_DIR), str(COLLECTOR_DIR / 'ui')],
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
