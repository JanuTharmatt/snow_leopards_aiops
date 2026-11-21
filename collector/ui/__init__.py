"""
Collector Control Center UI Package.
Phase 2.5.
"""

from .service_controller import service_controller, CollectorServiceController
from .state_manager import state_manager, CollectorStateManager
from .autostart import autostart_manager, WindowsAutoStartManager
from .tray import SystemTrayManager
from .app import CollectorControlCenterApp, launch_app

__all__ = [
    "service_controller",
    "CollectorServiceController",
    "state_manager",
    "CollectorStateManager",
    "autostart_manager",
    "WindowsAutoStartManager",
    "SystemTrayManager",
    "CollectorControlCenterApp",
    "launch_app",
]
