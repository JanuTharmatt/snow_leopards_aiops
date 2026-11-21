"""
Collector Control Center UI Package.
Phase 2.5.
"""

try:
    from .service_controller import service_controller, CollectorServiceController
except Exception:
    service_controller, CollectorServiceController = None, None

try:
    from .state_manager import state_manager, CollectorStateManager
except Exception:
    state_manager, CollectorStateManager = None, None

try:
    from .autostart import autostart_manager, WindowsAutoStartManager
except Exception:
    autostart_manager, WindowsAutoStartManager = None, None

try:
    from .tray import SystemTrayManager
except Exception:
    SystemTrayManager = None

try:
    from .app import CollectorControlCenterApp, launch_app
except Exception:
    CollectorControlCenterApp, launch_app = None, None

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
