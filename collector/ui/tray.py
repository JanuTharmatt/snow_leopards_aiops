"""
System Tray Support Module for Collector Control Center.
Feature 11: System Tray Support.
Uses pystray to run a background notification tray icon.
Ensures that when the UI window is closed, the application minimizes to tray
and the Collector Service remains fully active.
"""

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger("AIOps.Tray")

PIL_AVAILABLE = False
try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except (ImportError, ModuleNotFoundError) as err:
    logger.warning("PIL not available in runtime environment: %s", err)
    Image = None
    ImageDraw = None


def create_tray_icon_image(size: int = 64):
    """
    Dynamically generates an icon using PIL.
    Renders an emerald green & deep navy privacy shield.
    """
    if not PIL_AVAILABLE or Image is None or ImageDraw is None:
        return None

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Outer shield shape
    shield_points = [
        (size // 2, 4),
        (size - 8, 12),
        (size - 8, size // 2),
        (size // 2, size - 4),
        (8, size // 2),
        (8, 12),
    ]
    draw.polygon(shield_points, fill=(16, 185, 129, 255), outline=(5, 150, 105, 255))

    # Inner circular radar/check
    draw.ellipse([size // 4, size // 4, size * 3 // 4, size * 3 // 4], fill=(15, 23, 42, 255))
    draw.ellipse([size * 3 // 8, size * 3 // 8, size * 5 // 8, size * 5 // 8], fill=(52, 211, 153, 255))

    return image


class SystemTrayManager:
    """Manages the Windows notification area tray icon and menu."""

    def __init__(
        self,
        on_open_callback: Optional[Callable] = None,
        on_exit_callback: Optional[Callable] = None,
        get_status_callback: Optional[Callable] = None
    ):
        self.on_open_callback = on_open_callback
        self.on_exit_callback = on_exit_callback
        self.get_status_callback = get_status_callback
        self.icon = None
        self._tray_thread = None

    def start(self) -> None:
        """Starts the tray icon in a dedicated daemon thread."""
        try:
            import pystray
        except ImportError:
            # Graceful fallback if pystray not yet available
            return

        def setup_menu():
            status_text = "Status: Online"
            if self.get_status_callback:
                try:
                    status_text = f"Status: {self.get_status_callback()}"
                except Exception:
                    pass

            return pystray.Menu(
                pystray.MenuItem("Open Control Center", lambda icon, item: self._on_open()),
                pystray.MenuItem(status_text, lambda icon, item: None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit Control Center", lambda icon, item: self._on_exit())
            )

        image = create_tray_icon_image()
        self.icon = pystray.Icon(
            "PrivacyAIOpsCollector",
            image,
            "Privacy-First AIOps Collector",
            setup_menu()
        )

        def safe_run():
            try:
                self.icon.run()
            except Exception as exc:
                import logging
                logging.getLogger("AIOps.Tray").warning(f"System tray running in restricted environment: {exc}")

        self._tray_thread = threading.Thread(target=safe_run, daemon=True)
        self._tray_thread.start()

    def update_tooltip(self, text: str) -> None:
        if self.icon:
            self.icon.title = text

    def stop(self) -> None:
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass

    def _on_open(self) -> None:
        if self.on_open_callback:
            self.on_open_callback()

    def _on_exit(self) -> None:
        if self.on_exit_callback:
            self.on_exit_callback()
        self.stop()
