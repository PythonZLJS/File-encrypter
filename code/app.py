"""Liquid-glass GUI and background tasks. Launch with python cryptvault.py."""

import html
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QObject,
    QPoint,
    QRect,
    QRunnable,
    QSettings,
    QSize,
    Qt,
    QThreadPool,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QFontDatabase,
    QLinearGradient,
    QPainter,
    QPalette,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# ========================================================================
# CRYPTO ENGINE  (streaming - constant memory use regardless of file size)
# ========================================================================
from crypto_engine import (
    CIPHER_NAMES,
    ENCRYPTION_TYPES,
    Cancelled,
    CryptoError,
    decrypt_stream,
    describe_encryption_type,
    encrypt_stream,
    generate_password,
    human_size,
    password_strength,
    publish_file,
    secret_with_keyfile,
    sha256_of_file,
    shred_path,
    snapshot_tree,
    source_signature,
    unzip_file_to_folder,
    validate_source,
    verify_password_quick,
    verify_snapshot,
    zip_folder_to_file,
)


def open_in_file_manager(path: Path):
    path = str(path)
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


# ========================================================================
# BACKGROUND TASKS (QThreadPool - processes several files in parallel,
# using multiple CPU cores at once instead of one file at a time)
# ========================================================================
class TaskSignals(QObject):
    progress = Signal(str, int)
    done = Signal(str, str, float, object)
    failed = Signal(str, str)
    cancelled = Signal(str)


class UtilitySignals(QObject):
    finished = Signal(str, str)


class UtilityTask(QRunnable):
    def __init__(self, kind, callback):
        super().__init__()
        self.kind = kind
        self.callback = callback
        self.cancel_event = threading.Event()
        self.signals = UtilitySignals()

    def run(self):
        try:
            message = self.callback(self.cancel_event)
        except Cancelled:
            message = f"[{self.kind.upper()}] Cancelled."
        except Exception as exc:
            message = f"[{self.kind.upper()}] Could not complete: {exc}"
        finally:
            self.callback = None
        self.signals.finished.emit(self.kind, message)


class CryptoTask(QRunnable):
    def __init__(
        self,
        mode,
        path,
        secret,
        cipher_ids,
        preset,
        shred,
        output_dir,
        cancel_event,
        compress_folders=True,
    ):
        super().__init__()
        self.mode = mode
        self.path = Path(path)
        self.secret = secret
        self.cipher_ids = cipher_ids  # only used for encrypt; decrypt auto-detects
        self.preset = preset
        self.shred = shred
        self.output_dir = Path(output_dir) if output_dir else None
        self.cancel_event = cancel_event
        self.compress_folders = compress_folders
        self.signals = TaskSignals()
        self.keyfile_path = None
        self.keyfile_signature = None
        self._last_progress = -1

    def _cancel_check(self):
        return self.cancel_event.is_set()

    def run(self):
        start = time.time()
        try:
            if self._cancel_check():
                self.signals.cancelled.emit(str(self.path))
                return
            if self.keyfile_path:
                self.secret = secret_with_keyfile(
                    self.secret,
                    self.keyfile_path,
                    self._cancel_check,
                    self.keyfile_signature,
                )
            if self.mode == "encrypt":
                output = self._encrypt()
            else:
                output = self._decrypt()
            size = Path(output).stat().st_size if Path(output).is_file() else 0
            self.signals.done.emit(
                str(self.path), str(output), time.time() - start, size
            )
        except Cancelled:
            self.signals.cancelled.emit(str(self.path))
        except Exception as e:
            self.signals.failed.emit(str(self.path), str(e))
        finally:
            self.secret = b""

    def _progress(self, value):
        value = max(0, min(100, int(value)))
        if value != self._last_progress:
            self._last_progress = value
            self.signals.progress.emit(str(self.path), value)

    def _dest_dir_for(self, original: Path) -> Path:
        return self.output_dir if self.output_dir else original.parent

    def _encrypt(self):
        validate_source(self.path)
        is_folder = self.path.is_dir()
        dest_dir = self._dest_dir_for(self.path)
        if is_folder and (
            dest_dir.resolve() == self.path.resolve()
            or self.path.resolve() in dest_dir.resolve().parents
        ):
            raise CryptoError("Choose an output folder outside the input folder.")
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_name = dest_dir / (self.path.name + ".cvlt")
        if os.path.lexists(out_name):
            raise CryptoError(f"Output already exists: {out_name}")
        snapshot = snapshot_tree(self.path, self._cancel_check) if self.shred else None
        if is_folder:
            with tempfile.TemporaryDirectory(
                prefix=".cryptvault-", dir=dest_dir
            ) as temporary:
                tmp_zip = Path(temporary) / "folder.zip"
                zip_folder_to_file(
                    self.path,
                    tmp_zip,
                    compress=self.compress_folders,
                    progress_cb=lambda p: self._progress(int(p * 0.3)),
                    cancel_check=self._cancel_check,
                    snapshot=snapshot,
                )
                encrypt_stream(
                    tmp_zip,
                    out_name,
                    self.secret,
                    self.cipher_ids,
                    True,
                    self.preset,
                    progress_cb=lambda p: self._progress(30 + int(p * 0.7)),
                    cancel_check=self._cancel_check,
                )
        else:
            encrypt_stream(
                self.path,
                out_name,
                self.secret,
                self.cipher_ids,
                False,
                self.preset,
                progress_cb=self._progress,
                cancel_check=self._cancel_check,
            )
        if self.shred:
            if self._cancel_check():
                return out_name
            verify_snapshot(self.path, snapshot, self._cancel_check)
            shred_path(self.path)
        return out_name

    def _decrypt(self):
        validate_source(self.path)
        dest_dir = self._dest_dir_for(self.path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        target = dest_dir / (
            self.path.stem
            if self.path.suffix.lower() == ".cvlt"
            else self.path.name + ".decrypted"
        )
        original_stat = self.path.stat()
        with self.path.open("rb") as source:
            legacy = source.read(4) == b"CVL3"
        if legacy and self.shred:
            raise CryptoError(
                "Legacy v3 headers are unauthenticated. Disable original deletion to recover this file."
            )
        # Temporary plaintext stays on the chosen output filesystem.
        with tempfile.TemporaryDirectory(
            prefix=".cryptvault-", dir=dest_dir
        ) as temporary:
            tmp_out = Path(temporary) / "plaintext"
            is_folder = decrypt_stream(
                self.path,
                tmp_out,
                self.secret,
                progress_cb=lambda p: self._progress(int(p * 0.8)),
                cancel_check=self._cancel_check,
            )
            if self._cancel_check():
                raise Cancelled()
            if is_folder:
                result = dest_dir / (target.name + "_decrypted")
                unzip_file_to_folder(tmp_out, result, cancel_check=self._cancel_check)
            else:
                if os.path.lexists(target):
                    raise CryptoError(f"Output already exists: {target}")
                publish_file(tmp_out, target)
                result = target
        if self.shred and not self._cancel_check():
            validate_source(self.path)
            current = self.path.stat()
            if (current.st_ino, current.st_size, current.st_mtime_ns) != (
                original_stat.st_ino,
                original_stat.st_size,
                original_stat.st_mtime_ns,
            ):
                raise CryptoError(
                    "Output saved, but input changed; original was not deleted."
                )
            shred_path(self.path)
        return result


# ========================================================================
# FLOW LAYOUT — used inside each tab so button rows wrap onto a new line
# instead of ever clipping or overflowing, at any window width.
# ========================================================================
class FlowLayout(QLayout):
    def __init__(self, parent=None, margin=0, spacing=8):
        super().__init__(parent)
        self.setContentsMargins(margin, margin, margin, margin)
        self.setSpacing(spacing)
        self._items = []

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        m = self.contentsMargins()
        size += QSize(m.left() + m.right(), m.top() + m.bottom())
        return size

    def _do_layout(self, rect, test_only):
        x, y = rect.x(), rect.y()
        line_height = 0
        spacing = self.spacing()

        for item in self._items:
            hint = item.sizeHint()
            next_x = x + hint.width() + spacing
            if next_x - spacing > rect.right() and line_height > 0:
                x = rect.x()
                y = y + line_height + spacing
                next_x = x + hint.width() + spacing
                line_height = 0

            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), hint))

            x = next_x
            line_height = max(line_height, hint.height())

        return y + line_height - rect.y()


# ========================================================================
# LIQUID-GLASS STYLING (dark + light variants)
# ========================================================================
_QSS_TEMPLATE = """
QWidget#GlassPanel {
    background-color: §PANEL_BG§;
    border-radius: 26px;
    border: 1px solid §PANEL_BORDER§;
}
QWidget#Card {
    background-color: §CARD_BG§;
    border-radius: 16px;
    border: 1px solid §PANEL_BORDER§;
}
QLabel#Title { color: §TITLE§; font-size: 30px; font-weight: 700; letter-spacing: 0.5px; }
QLabel#Subtitle { color: §SUBTITLE§; font-size: 12px; }
QLabel { color: §TEXT§; font-size: 13px; }
QLabel#SectionTag { color: §TAG§; font-size: 11px; font-weight: 800; letter-spacing: 1.2px; }
QLabel#RowName { color: §TEXT_STRONG§; font-size: 12px; font-weight: 600; }
QLabel#RowStatus { color: §TAG§; font-size: 11px; }
QLineEdit, QComboBox {
    background-color: §INPUT_BG§;
    border: 1px solid §INPUT_BORDER§;
    border-radius: 12px;
    padding: 9px 12px;
    color: §TEXT_STRONG§;
    font-size: 13px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid rgba(120,170,255,230); }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background-color: §DROPDOWN_BG§;
    color: §TEXT_STRONG§;
    selection-background-color: rgba(120,170,255,180);
    border-radius: 8px;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #438df7, stop:1 #2869dc);
    border: 1px solid rgba(255,255,255,90);
    border-radius: 14px;
    padding: 10px 16px;
    color: white;
    font-size: 13px;
    font-weight: 700;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #5da1ff, stop:1 #377ce9);
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(100, 140, 220, 245), stop:1 rgba(90, 125, 210, 245));
}
QPushButton:disabled {
    background: rgba(120,120,140,90);
    color: rgba(255,255,255,130);
    border: 1px solid rgba(255,255,255,40);
}
QPushButton#Secondary {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    color: §TEXT_STRONG§;
}
QPushButton#Secondary:hover { background: §SECONDARY_BTN_HOVER§; }
QPushButton#Info {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    border-radius: 16px;
    color: §TEXT_STRONG§;
    padding: 8px 12px;
    font-weight: 900;
}
QPushButton#Info:hover { background: §SECONDARY_BTN_HOVER§; }
QPushButton#Danger {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(240, 110, 110, 235), stop:1 rgba(210, 75, 75, 235));
}
QPushButton#Danger:disabled {
    background: §SECONDARY_BTN_BG§;
    color: §SUBTITLE§;
    border: 1px solid §INPUT_BORDER§;
}
QPushButton#Danger:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(250, 130, 130, 245), stop:1 rgba(225, 90, 90, 245));
}
QCheckBox { color: §TEXT§; font-size: 13px; spacing: 8px; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 6px;
    border: 1px solid §INPUT_BORDER§;
    background: §INPUT_BG§;
}
QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #438df7, stop:1 #2869dc);
    border: 1px solid rgba(255,255,255,180);
}
QProgressBar {
    background-color: §INPUT_BG§;
    border-radius: 8px;
    height: 14px;
    text-align: center;
    color: §TEXT_STRONG§;
    border: 1px solid §INPUT_BORDER§;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(120, 200, 255, 235), stop:1 rgba(150, 150, 255, 235));
    border-radius: 7px;
}
QListWidget {
    background-color: §CARD_BG§;
    border: 1px dashed §INPUT_BORDER§;
    border-radius: 18px;
    padding: 8px;
    color: §TEXT_STRONG§;
    font-size: 12px;
}
QListWidget::item { border: 1px solid §PANEL_BORDER§; padding: 4px; border-radius: 12px; }
QListWidget::item:selected { background: rgba(70,140,240,35); }
QListWidget::item:selected { background: transparent; }
QTextEdit {
    background-color: §LOG_BG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 14px;
    color: §LOG_TEXT§;
    font-size: 11px;
    font-family: Consolas, monospace;
    padding: 6px;
}
QLabel#Heading { color: §TEXT_STRONG§; font-size: 23px; font-weight: 600; }
QLabel#Badge { color: §TAG§; background: §CARD_BG§; border: 1px solid §INPUT_BORDER§;
    border-radius: 12px; padding: 6px 10px; font-size: 10px; font-weight: 700; }
QLabel#Strength { font-size: 12px; font-weight: 700; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: §SCROLLBAR§; border-radius: 5px; min-height: 30px; }
QMenu {
    background-color: §DROPDOWN_BG§;
    color: §TEXT_STRONG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 8px;
}
QMenu::item:selected { background: rgba(120,170,255,150); }
QTabWidget::pane {
    border: none;
    background: transparent;
    top: -1px;
}
QTabBar::tab {
    background: §SECONDARY_BTN_BG§;
    border: 1px solid §SECONDARY_BTN_BORDER§;
    color: §TEXT_STRONG§;
    padding: 9px 16px;
    margin-right: 6px;
    border-radius: 16px;
    font-weight: 700;
    font-size: 12px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #438df7, stop:1 #2869dc);
    color: white;
}
QDialog { background-color: §DIALOG_BG§; }
QTableWidget {
    background-color: §CARD_BG§;
    color: §TEXT_STRONG§;
    border: 1px solid §PANEL_BORDER§;
    border-radius: 12px;
    gridline-color: §PANEL_BORDER§;
    font-size: 12px;
}
QHeaderView::section {
    background-color: §SECONDARY_BTN_BG§;
    color: §TEXT_STRONG§;
    padding: 6px;
    border: none;
    font-weight: 700;
}
"""

_DARK_TOKENS = {
    "§PANEL_BG§": "rgba(18, 29, 52, 215)",
    "§PANEL_BORDER§": "rgba(210, 228, 255, 48)",
    "§CARD_BG§": "rgba(233, 243, 255, 14)",
    "§TITLE§": "#f5f8ff",
    "§SUBTITLE§": "#b2c1d9",
    "§TEXT§": "#dce6f5",
    "§TEXT_STRONG§": "#f4f8ff",
    "§TAG§": "#afc6e8",
    "§INPUT_BG§": "rgba(9, 18, 38, 150)",
    "§INPUT_BORDER§": "rgba(192, 217, 255, 52)",
    "§DROPDOWN_BG§": "#1d2c47",
    "§DIALOG_BG§": "#14223b",
    "§SECONDARY_BTN_BG§": "rgba(235, 246, 255, 18)",
    "§SECONDARY_BTN_BORDER§": "rgba(222, 239, 255, 48)",
    "§SECONDARY_BTN_HOVER§": "rgba(213, 234, 255, 36)",
    "§LOG_BG§": "rgba(7, 17, 35, 145)",
    "§LOG_TEXT§": "#dce6f5",
    "§SCROLLBAR§": "rgba(205, 224, 255, 65)",
}
_LIGHT_TOKENS = {
    "§PANEL_BG§": "rgba(255, 255, 255, 170)",
    "§PANEL_BORDER§": "rgba(255, 255, 255, 240)",
    "§CARD_BG§": "rgba(255, 255, 255, 120)",
    "§TITLE§": "#172c49",
    "§SUBTITLE§": "#52647f",
    "§TEXT§": "#354963",
    "§TEXT_STRONG§": "#182e4e",
    "§TAG§": "#536b8c",
    "§INPUT_BG§": "rgba(255, 255, 255, 210)",
    "§INPUT_BORDER§": "rgba(79, 111, 156, 50)",
    "§DROPDOWN_BG§": "#f3f7fd",
    "§DIALOG_BG§": "#eff4fc",
    "§SECONDARY_BTN_BG§": "rgba(255, 255, 255, 165)",
    "§SECONDARY_BTN_BORDER§": "rgba(94, 123, 167, 48)",
    "§SECONDARY_BTN_HOVER§": "rgba(224, 238, 255, 210)",
    "§LOG_BG§": "rgba(255, 255, 255, 150)",
    "§LOG_TEXT§": "#263e5f",
    "§SCROLLBAR§": "rgba(71, 103, 149, 70)",
}


def build_qss(dark: bool) -> str:
    qss = _QSS_TEMPLATE
    tokens = _DARK_TOKENS if dark else _LIGHT_TOKENS
    for token, value in tokens.items():
        qss = qss.replace(token, value)
    return qss


class GradientBackground(QWidget):
    """Paints a soft, multi-blob iOS-style diffused backdrop - several
    overlapping radial gradients blended together, which is what gives a
    'liquid glass' scene its depth instead of a flat linear gradient.
    Pure paintEvent-based so it costs nothing extra and never breaks on
    resize; no extra libraries required."""

    def __init__(self, dark=True):
        super().__init__()
        self.dark = dark

    def set_dark(self, dark):
        self.dark = dark
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = max(self.width(), 1), max(self.height(), 1)

        base = QLinearGradient(0, 0, w, h)
        if self.dark:
            base.setColorAt(0.0, QColor(20, 24, 46))
            base.setColorAt(0.5, QColor(42, 30, 74))
            base.setColorAt(1.0, QColor(14, 58, 84))
        else:
            base.setColorAt(0.0, QColor(232, 238, 255))
            base.setColorAt(0.5, QColor(240, 228, 252))
            base.setColorAt(1.0, QColor(222, 245, 248))
        painter.fillRect(self.rect(), QBrush(base))
        sheen = QLinearGradient(0, 0, w, h * 0.75)
        sheen.setColorAt(0, QColor(255, 255, 255, 28 if self.dark else 110))
        sheen.setColorAt(0.45, QColor(255, 255, 255, 0))
        sheen.setColorAt(1, QColor(255, 255, 255, 16))
        painter.fillRect(self.rect(), QBrush(sheen))

        blobs_dark = [
            (0.15, 0.20, 0.55, QColor(130, 100, 255, 100)),
            (0.85, 0.15, 0.50, QColor(90, 190, 255, 90)),
            (0.75, 0.85, 0.60, QColor(255, 120, 190, 70)),
            (0.20, 0.85, 0.45, QColor(80, 220, 200, 70)),
        ]
        blobs_light = [
            (0.15, 0.20, 0.55, QColor(170, 150, 255, 90)),
            (0.85, 0.15, 0.50, QColor(140, 210, 255, 90)),
            (0.75, 0.85, 0.60, QColor(255, 170, 210, 80)),
            (0.20, 0.85, 0.45, QColor(150, 235, 220, 80)),
        ]
        blobs = blobs_dark if self.dark else blobs_light

        for fx, fy, frad, color in blobs:
            cx, cy = w * fx, h * fy
            radius = max(w, h) * frad
            radial = QRadialGradient(cx, cy, radius)
            radial.setColorAt(0.0, color)
            transparent = QColor(color)
            transparent.setAlpha(0)
            radial.setColorAt(1.0, transparent)
            painter.setBrush(QBrush(radial))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPoint(int(cx), int(cy)), int(radius), int(radius))


class GlassPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("GlassPanel")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)


class Card(QFrame):
    """A smaller frosted sub-panel used to group related controls -
    gives the layout visual hierarchy instead of one long flat stack."""

    def __init__(self):
        super().__init__()
        self.setObjectName("Card")


class DropList(QListWidget):
    paths_added = Signal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumHeight(160)
        self.setSpacing(4)
        # QListWidget is a scroll area internally too - its viewport
        # auto-fills with an opaque background by default, which can hide
        # the frosted backdrop behind it. Turning off auto-fill (not a
        # stylesheet override, which would wipe child widget styling too)
        # fixes that without touching anything else.
        self.viewport().setAutoFillBackground(False)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.count():
            return
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.Antialiasing)
        dark = self.palette().windowText().color().lightness() > 160
        painter.setPen(QColor("#dbeafe" if dark else "#334768"))
        center = self.viewport().rect().center()
        painter.setFont(QFont(self.font().family(), 25))
        painter.drawText(
            QRect(0, center.y() - 62, self.viewport().width(), 40), Qt.AlignCenter, "↓"
        )
        painter.setFont(QFont(self.font().family(), 13, QFont.DemiBold))
        painter.drawText(
            QRect(0, center.y() - 15, self.viewport().width(), 30),
            Qt.AlignCenter,
            "Drop files & folders here",
        )
        painter.setFont(QFont(self.font().family(), 10))
        painter.drawText(
            QRect(0, center.y() + 20, self.viewport().width(), 28),
            Qt.AlignCenter,
            "or use Add Files and Add Folder below",
        )
        painter.end()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = [
            url.toLocalFile() for url in event.mimeData().urls() if url.toLocalFile()
        ]
        if paths:
            self.paths_added.emit(paths)
        event.acceptProposedAction()


class FileRowWidget(QWidget):
    """One row in the file list: name, a real inline progress bar, and a
    status label. This is what makes per-file progress genuinely visible
    during encryption/decryption, not just text changing in place."""

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        kind = "📁" if Path(path).is_dir() else "📄"
        self.name_label = QLabel(f"{kind}  {Path(path).name}")
        self.name_label.setTextFormat(Qt.PlainText)
        self.name_label.setMinimumWidth(0)
        self.name_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.name_label.setToolTip(str(path))
        self.name_label.setObjectName("RowName")
        self.setToolTip(str(path))
        self.status_label = QLabel("Queued")
        self.status_label.setObjectName("RowStatus")
        top_row.addWidget(self.name_label, stretch=1)
        top_row.addWidget(self.status_label)
        layout.addLayout(top_row)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(10)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

    def set_progress(self, percent):
        self.progress.setValue(percent)
        self.status_label.setText(f"{percent}%")

    def set_status(self, text, done=False, failed=False, cancelled=False):
        self.status_label.setText(text)
        if done:
            self.progress.setValue(100)
        elif failed or cancelled:
            pass  # leave progress bar wherever it stopped


# ========================================================================
# ENCRYPTION TYPE INFO DIALOG (expanded) + COMPARISON DIALOG
# ========================================================================
SPEED_RATING = {
    "AES-256-GCM (Standard)": ("Very fast", "★★★★★"),
    "ChaCha20-Poly1305 (Software-Friendly)": ("Fast", "★★★★☆"),
    "AES-256-GCM-SIV (Misuse-Resistant)": ("Fast", "★★★★☆"),
    "AES-256-OCB3 (High Performance)": ("Very fast", "★★★★★"),
    "AES-256-CCM (Compact / IoT Standard)": ("Moderate", "★★★☆☆"),
    "Double Shield (AES-GCM + ChaCha20)": ("Slower (2 layers)", "★★☆☆☆"),
    "Fort Knox (Triple Layer: AES-GCM + ChaCha20 + AES-GCM-SIV)": (
        "Slowest (3 layers)",
        "★☆☆☆☆",
    ),
}

REAL_WORLD_USE = {
    "AES-256-GCM (Standard)": "Used extensively in TLS (the encryption behind HTTPS), many VPNs, and disk "
    "encryption products. The most common authenticated cipher in production software.",
    "ChaCha20-Poly1305 (Software-Friendly)": "Used as an alternative cipher suite in TLS 1.3, and is the sole cipher used by "
    "the WireGuard VPN protocol.",
    "AES-256-GCM-SIV (Misuse-Resistant)": "Standardized in RFC 8452, developed with input from Google engineers specifically "
    "to reduce the damage from accidental nonce reuse in large-scale systems.",
    "AES-256-OCB3 (High Performance)": "Standardized in RFC 7253. Its adoption was historically limited by patents that "
    "held until 2021 - it's now free to use anywhere, and is prized in performance-"
    "critical systems that need maximum throughput.",
    "AES-256-CCM (Compact / IoT Standard)": "The cipher behind WPA2 Wi-Fi security (CCMP), Bluetooth Low Energy, and Zigbee - "
    "chosen there for its compact, well-analyzed design suited to constrained devices.",
    "Double Shield (AES-GCM + ChaCha20)": "A layered construction, not a single standardized cipher - used here purely for "
    "extra defense-in-depth on your own files.",
    "Fort Knox (Triple Layer: AES-GCM + ChaCha20 + AES-GCM-SIV)": "A layered construction combining three independent, standardized ciphers for "
    "maximum redundancy against any single algorithm ever being broken.",
}


class EncryptionInfoDialog(QDialog):
    def __init__(self, parent, encryption_type, on_compare):
        super().__init__(parent)
        self.setWindowTitle("Encryption Type Info")
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        et = encryption_type
        cipher_chain = " → ".join(CIPHER_NAMES[c] for c in et["ciphers"])
        speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))

        title = QLabel(et["name"])
        title.setObjectName("Title")
        title.setStyleSheet("font-size: 18px;")
        title.setWordWrap(True)
        layout.addWidget(title)

        chain_label = QLabel(f"Algorithm chain: {cipher_chain}")
        chain_label.setWordWrap(True)
        chain_label.setObjectName("Subtitle")
        layout.addWidget(chain_label)

        speed_row = QLabel(f"<b>Relative speed:</b> {speed_label}  {stars}")
        speed_row.setTextFormat(Qt.RichText)
        layout.addWidget(speed_row)

        summary = QLabel(et["summary"])
        summary.setWordWrap(True)
        layout.addWidget(summary)

        pros_card = Card()
        pros_layout = QVBoxLayout(pros_card)
        pros_title = QLabel("✅ Good at")
        pros_title.setStyleSheet("font-weight: 800;")
        pros_layout.addWidget(pros_title)
        pros_text = QLabel(et["pros"])
        pros_text.setWordWrap(True)
        pros_layout.addWidget(pros_text)
        layout.addWidget(pros_card)

        cons_card = Card()
        cons_layout = QVBoxLayout(cons_card)
        cons_title = QLabel("⚠️ Trade-offs")
        cons_title.setStyleSheet("font-weight: 800;")
        cons_layout.addWidget(cons_title)
        cons_text = QLabel(et["cons"])
        cons_text.setWordWrap(True)
        cons_layout.addWidget(cons_text)
        layout.addWidget(cons_card)

        used_card = Card()
        used_layout = QVBoxLayout(used_card)
        used_title = QLabel("🌍 Where it's used in the real world")
        used_title.setStyleSheet("font-weight: 800;")
        used_layout.addWidget(used_title)
        used_text = QLabel(REAL_WORLD_USE.get(et["name"], ""))
        used_text.setWordWrap(True)
        used_layout.addWidget(used_text)
        layout.addWidget(used_card)

        btn_row = QHBoxLayout()
        btn_compare = QPushButton("Compare All Types")
        btn_compare.setObjectName("Secondary")
        btn_compare.clicked.connect(lambda: (self.close(), on_compare()))
        btn_close = QPushButton("Close")
        btn_row.addWidget(btn_compare)
        btn_row.addWidget(btn_close)
        btn_close.clicked.connect(self.close)
        layout.addLayout(btn_row)


class ComparisonDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Compare Encryption Types")
        self.resize(760, 420)
        layout = QVBoxLayout(self)

        intro = QLabel(
            "All of these are strong, modern authenticated ciphers - none is "
            '"weak". The differences are speed, hardware support, and how many '
            "independent layers are used."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        table = QTableWidget(len(ENCRYPTION_TYPES), 4)
        table.setHorizontalHeaderLabels(
            ["Type", "Algorithm Chain", "Relative Speed", "Best For"]
        )
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setWordWrap(True)

        for row, et in enumerate(ENCRYPTION_TYPES):
            chain = " → ".join(CIPHER_NAMES[c] for c in et["ciphers"])
            speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))
            table.setItem(row, 0, QTableWidgetItem(et["name"]))
            table.setItem(row, 1, QTableWidgetItem(chain))
            table.setItem(row, 2, QTableWidgetItem(f"{speed_label} {stars}"))
            table.setItem(row, 3, QTableWidgetItem(et["summary"]))
            table.resizeRowToContents(row)

        layout.addWidget(table)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        layout.addWidget(btn_close)


# ========================================================================
# MAIN WINDOW
# ========================================================================
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptVault")
        self.setMinimumSize(460, 580)

        self.settings = QSettings("CryptVault", "CryptVault")

        self.selected_paths = []
        self.row_widgets = {}  # path -> FileRowWidget
        self.output_dir = self._setting("output_dir", "", str) or None
        self.last_dir = self._setting("last_dir", str(Path.home()), str)
        self.dark_mode = self._setting("dark_mode", False, bool)
        self.last_output_dir = None
        self.keyfile_path = None

        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(2)
        self.active_tasks = {}
        self.utility_tasks = {}
        self._task_progress = {}
        self._progress_total = 0
        self._batch_failed = 0
        self._batch_cancelled = 0
        self._closing = False
        self.cancel_event = threading.Event()
        self.total_tasks = 0
        self.completed_tasks = 0
        self.batch_start_time = None

        self.idle_timer = QTimer(self)
        self.idle_timer.setInterval(5 * 60 * 1000)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self.auto_clear_passwords)

        self._build_ui()
        self._apply_theme()
        self._restore_settings()

        size = self._setting("window_size", None)
        size = size if isinstance(size, QSize) and size.isValid() else QSize(920, 880)
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry().size() if screen else QSize(1280, 960)
        self.resize(size.boundedTo(available).expandedTo(self.minimumSize()))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "local_badge"):
            self.local_badge.setVisible(self.width() >= 640)
            self.footer_note.setVisible(self.width() >= 640)

    def _setting(self, key, default=None, value_type=None):
        try:
            if value_type is None:
                return self.settings.value(key, default)
            return self.settings.value(key, default, value_type)
        except (TypeError, ValueError, OverflowError):
            return default

    # ---------------- UI construction ----------------
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self.bg = GradientBackground(dark=True)
        bg_layout = QVBoxLayout(self.bg)
        bg_layout.setContentsMargins(24, 24, 24, 16)
        bg_layout.setSpacing(12)

        header_row = QHBoxLayout()
        wordmark = QVBoxLayout()
        wordmark.setSpacing(2)
        title = QLabel("CryptVault")
        title.setObjectName("Title")
        subtitle = QLabel("Your files. Your password. Your space.")
        subtitle.setObjectName("Subtitle")
        subtitle.setWordWrap(True)
        wordmark.addWidget(title)
        wordmark.addWidget(subtitle)
        header_row.addLayout(wordmark, stretch=1)
        badge = QLabel("●  ON YOUR DEVICE")
        badge.setObjectName("Badge")
        self.local_badge = badge
        header_row.addWidget(badge)
        self.theme_btn = QPushButton("Dark")
        self.theme_btn.setObjectName("Secondary")
        self.theme_btn.setToolTip("Switch between light and dark glass")
        self.theme_btn.clicked.connect(self.toggle_theme)
        header_row.addWidget(self.theme_btn)
        bg_layout.addLayout(header_row)

        panel = GlassPanel()
        panel_outer = QVBoxLayout(panel)
        panel_outer.setContentsMargins(18, 16, 18, 18)
        panel_outer.setSpacing(10)

        self.tabs = QTabWidget()
        panel_outer.addWidget(self.tabs)

        self.tabs.addTab(self._build_files_tab(), "Files")
        self.tabs.addTab(self._build_encryption_tab(), "Ciphers")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_log_tab(), "Activity")

        bg_layout.addWidget(panel, stretch=1)
        footer = QHBoxLayout()
        self.status_label = QLabel("Ready when you are")
        self.status_label.setObjectName("Subtitle")
        footer.addWidget(self.status_label, stretch=1)
        footer_note = QLabel("No accounts. No cloud.")
        footer_note.setObjectName("Subtitle")
        self.footer_note = footer_note
        footer.addWidget(footer_note)
        bg_layout.addLayout(footer)
        root.addWidget(self.bg)

    def _wrap_scroll(self, inner_widget):
        # QScrollArea's viewport auto-fills with an opaque background by
        # default (from the widget palette), which silently painted over
        # the glass panel and made text hard to read - especially in light
        # mode. Disabling auto-fill (a plain property, not a stylesheet)
        # fixes that without cascading into and wiping child widget styles
        # the way an unscoped "background: transparent" QSS rule would.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.viewport().setAutoFillBackground(False)
        scroll.setWidget(inner_widget)
        inner_widget.setAutoFillBackground(False)
        return scroll

    def _build_files_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)
        layout.setContentsMargins(4, 16, 4, 4)
        intro_row = QHBoxLayout()
        intro = QLabel("Make private, stay private.")
        intro.setObjectName("Heading")
        self.queue_label = QLabel("0 items")
        self.queue_label.setObjectName("Badge")
        intro_row.addWidget(intro, stretch=1)
        intro_row.addWidget(self.queue_label)
        layout.addLayout(intro_row)
        description = QLabel("Add files or folders, then choose Encrypt or Decrypt.")
        description.setObjectName("Subtitle")
        description.setWordWrap(True)
        layout.addWidget(description)
        self.file_list = DropList()
        self.file_list.paths_added.connect(self.add_paths)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.file_list, stretch=2)

        self.picker_buttons = []
        picker_row = FlowLayout(spacing=8)
        for label, slot in [
            ("Add Files", self.choose_files),
            ("Add Folder", self.choose_folder),
            ("Remove Selected", self.remove_selected),
            ("Clear All", self.clear_list),
        ]:
            btn = QPushButton(label)
            btn.setObjectName("Secondary")
            btn.clicked.connect(slot)
            self.picker_buttons.append(btn)
            picker_row.addWidget(btn)
        layout.addLayout(picker_row)

        pw_card = Card()
        pw_layout = QVBoxLayout(pw_card)
        pw_layout.setContentsMargins(18, 16, 18, 16)
        pw_layout.setSpacing(10)
        pw_layout.addWidget(self._tag("YOUR PASSWORD"))
        pw_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter a strong password")
        self.password_input.setMinimumWidth(120)
        self.password_input.textChanged.connect(self.on_password_activity)
        btn_generate = QPushButton("Generate")
        btn_generate.setObjectName("Secondary")
        btn_generate.clicked.connect(self.fill_generated_password)
        pw_row.addWidget(self.password_input)
        pw_row.addWidget(btn_generate)
        pw_layout.addLayout(pw_row)

        self.strength_label = QLabel("")
        self.strength_label.setObjectName("Strength")
        self.strength_label.hide()
        pw_layout.addWidget(self.strength_label)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm password (required for Encrypt)")
        self.confirm_input.textChanged.connect(self.on_password_activity)
        pw_layout.addWidget(self.confirm_input)

        row2 = FlowLayout(spacing=8)
        self.show_pw_checkbox = QCheckBox("Show password")
        self.show_pw_checkbox.stateChanged.connect(self.toggle_password_visibility)
        btn_verify = QPushButton("Verify Password")
        btn_verify.setObjectName("Secondary")
        btn_verify.clicked.connect(self.verify_password)
        row2.addWidget(self.show_pw_checkbox)
        row2.addWidget(btn_verify)
        pw_layout.addLayout(row2)
        layout.addWidget(pw_card)

        action_row = FlowLayout(spacing=8)
        self.btn_encrypt = QPushButton("Encrypt files  →")
        self.btn_encrypt.clicked.connect(self.start_encrypt)
        self.btn_decrypt = QPushButton("Decrypt files")
        self.btn_decrypt.setObjectName("Secondary")
        self.btn_decrypt.clicked.connect(self.start_decrypt)
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("Danger")
        self.btn_cancel.clicked.connect(self.cancel_batch)
        self.btn_cancel.setEnabled(False)
        action_row.addWidget(self.btn_encrypt)
        action_row.addWidget(self.btn_decrypt)
        action_row.addWidget(self.btn_cancel)
        layout.addLayout(action_row)

        self.destination_note = QLabel(
            "Saves beside the original · Existing files are kept"
        )
        self.destination_note.setObjectName("Subtitle")
        self.destination_note.setWordWrap(True)
        layout.addWidget(self.destination_note)
        self.overall_bar = QProgressBar()
        self.overall_bar.setValue(0)
        self.overall_bar.setFormat("%p%")
        layout.addWidget(self.overall_bar)

        return self._wrap_scroll(content)

    def _build_encryption_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        layout.addWidget(
            self._tag("ENCRYPTION TYPE  (decrypting never needs you to remember this)")
        )
        enc_row = FlowLayout(spacing=8)
        self.encryption_combo = QComboBox()
        self.encryption_combo.setMinimumWidth(220)
        self.encryption_combo.setMinimumContentsLength(20)
        self.encryption_combo.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon
        )
        for et in ENCRYPTION_TYPES:
            self.encryption_combo.addItem(et["name"])
        self.encryption_combo.setCurrentIndex(0)
        btn_info = QPushButton("ⓘ More Info")
        btn_info.setObjectName("Info")
        btn_info.clicked.connect(self.show_encryption_type_info)
        btn_compare = QPushButton("⇄ Compare All Types")
        btn_compare.setObjectName("Secondary")
        btn_compare.clicked.connect(self.show_comparison_dialog)
        enc_row.addWidget(self.encryption_combo)
        enc_row.addWidget(btn_info)
        enc_row.addWidget(btn_compare)
        layout.addLayout(enc_row)

        summary_card = Card()
        summary_layout = QVBoxLayout(summary_card)
        self.encryption_summary = QLabel(ENCRYPTION_TYPES[0]["summary"])
        self.encryption_summary.setWordWrap(True)
        summary_layout.addWidget(self.encryption_summary)
        self.encryption_speed = QLabel("")
        self.encryption_speed.setTextFormat(Qt.RichText)
        summary_layout.addWidget(self.encryption_speed)
        layout.addWidget(summary_card)
        self.encryption_combo.currentIndexChanged.connect(
            self._update_encryption_summary
        )
        self._update_encryption_summary(0)

        layout.addWidget(self._tag("PASSWORD SECURITY LEVEL"))
        sec_row = FlowLayout(spacing=8)
        sec_row.addWidget(QLabel("How expensive password cracking should be:"))
        self.security_combo = QComboBox()
        self.security_combo.addItems(
            ["Fast (16 MB)", "Balanced (32 MB)", "Paranoid (128 MB, recommended)"]
        )
        self.security_combo.setCurrentIndex(2)
        sec_row.addWidget(self.security_combo)
        layout.addLayout(sec_row)

        layout.addStretch()
        return self._wrap_scroll(content)

    def _build_settings_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        out_card = Card()
        out_layout = QVBoxLayout(out_card)
        out_layout.addWidget(self._tag("OUTPUT LOCATION"))
        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("(default: same folder as each file)")
        self.output_input.setReadOnly(True)
        out_layout.addWidget(self.output_input)
        out_row = FlowLayout(spacing=8)
        btn_browse_out = QPushButton("Browse")
        btn_browse_out.setObjectName("Secondary")
        btn_browse_out.clicked.connect(self.choose_output_dir)
        btn_reset_out = QPushButton("Reset")
        btn_reset_out.setObjectName("Secondary")
        btn_reset_out.clicked.connect(self.reset_output_dir)
        self.btn_open_output = QPushButton("Open Output Folder")
        self.btn_open_output.setObjectName("Secondary")
        self.btn_open_output.clicked.connect(self.open_output_folder)
        self.btn_open_output.setEnabled(False)
        out_row.addWidget(btn_browse_out)
        out_row.addWidget(btn_reset_out)
        out_row.addWidget(self.btn_open_output)
        out_layout.addLayout(out_row)
        layout.addWidget(out_card)

        key_card = Card()
        key_layout = QVBoxLayout(key_card)
        key_layout.addWidget(
            self._tag("KEYFILE (OPTIONAL - PASSWORD + FILE BOTH REQUIRED)")
        )
        self.keyfile_input = QLineEdit()
        self.keyfile_input.setPlaceholderText(
            "(none - password alone unlocks the file)"
        )
        self.keyfile_input.setReadOnly(True)
        key_layout.addWidget(self.keyfile_input)
        keyfile_row = FlowLayout(spacing=8)
        btn_choose_keyfile = QPushButton("Choose Keyfile")
        btn_choose_keyfile.setObjectName("Secondary")
        btn_choose_keyfile.clicked.connect(self.choose_keyfile)
        btn_generate_keyfile = QPushButton("Generate New Keyfile")
        btn_generate_keyfile.setObjectName("Secondary")
        btn_generate_keyfile.clicked.connect(self.generate_keyfile)
        btn_clear_keyfile = QPushButton("Clear Keyfile")
        btn_clear_keyfile.setObjectName("Secondary")
        btn_clear_keyfile.clicked.connect(self.clear_keyfile)
        keyfile_row.addWidget(btn_choose_keyfile)
        keyfile_row.addWidget(btn_generate_keyfile)
        keyfile_row.addWidget(btn_clear_keyfile)
        key_layout.addLayout(keyfile_row)
        layout.addWidget(key_card)

        opts_card = Card()
        opts_layout = QVBoxLayout(opts_card)
        opts_layout.addWidget(self._tag("OPTIONS"))
        self.shred_original = QCheckBox("Delete originals after success")
        self.shred_original.setToolTip(
            "Cannot guarantee erasure on SSDs, snapshots, backups, or journaled filesystems."
        )
        opts_layout.addWidget(self.shred_original)
        self.compress_folders = QCheckBox("Compress folders before encrypting")
        self.compress_folders.setChecked(True)
        opts_layout.addWidget(self.compress_folders)
        self.play_sound = QCheckBox("Play a sound when a batch finishes")
        opts_layout.addWidget(self.play_sound)
        layout.addWidget(opts_card)

        layout.addStretch()
        return self._wrap_scroll(content)

    def _build_log_tab(self):
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(10)

        log_header = FlowLayout(spacing=8)
        log_header.addWidget(self._tag("ACTIVITY LOG"))
        btn_save_log = QPushButton("Save Log")
        btn_save_log.setObjectName("Secondary")
        btn_save_log.clicked.connect(self.save_log)
        log_header.addWidget(btn_save_log)
        layout.addLayout(log_header)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.document().setMaximumBlockCount(2000)
        self.log_box.setMinimumHeight(200)
        layout.addWidget(self.log_box, stretch=1)

        return self._wrap_scroll(content)

    @staticmethod
    def _tag(text):
        lbl = QLabel(text)
        lbl.setObjectName("SectionTag")
        return lbl

    def closeEvent(self, event):
        if (
            self.total_tasks > self.completed_tasks
            or self.utility_tasks
            or self.pool.activeThreadCount()
        ):
            self._closing = True
            self.cancel_event.set()
            for task in self.utility_tasks.values():
                task.cancel_event.set()
            self.status_label.setText("Finishing safely…")
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        self.password_input.clear()
        self.confirm_input.clear()
        self.settings.setValue("last_dir", self.last_dir)
        self.settings.setValue("output_dir", self.output_dir or "")
        self.settings.setValue("dark_mode", self.dark_mode)
        self.settings.setValue("security_index", self.security_combo.currentIndex())
        self.settings.setValue("encryption_index", self.encryption_combo.currentIndex())
        self.settings.setValue("shred_original", self.shred_original.isChecked())
        self.settings.setValue("compress_folders", self.compress_folders.isChecked())
        self.settings.setValue("play_sound", self.play_sound.isChecked())
        self.settings.setValue("window_size", self.size())
        super().closeEvent(event)

    def _restore_settings(self):
        idx = self._setting("security_index", 2, int)
        self.security_combo.setCurrentIndex(idx if 0 <= idx < 3 else 2)
        enc_idx = self._setting("encryption_index", 0, int)
        if 0 <= enc_idx < len(ENCRYPTION_TYPES):
            self.encryption_combo.setCurrentIndex(enc_idx)
        self.shred_original.setChecked(False)
        self.compress_folders.setChecked(self._setting("compress_folders", True, bool))
        self.play_sound.setChecked(self._setting("play_sound", False, bool))
        if self.output_dir:
            self.output_input.setText(self.output_dir)
            self.destination_note.setText(
                f"Saves to {self.output_dir} · Existing files are kept"
            )

    # ---------------- Theme ----------------
    def _apply_theme(self):
        self.setStyleSheet(build_qss(self.dark_mode))
        self.bg.set_dark(self.dark_mode)
        palette = self.palette()
        palette.setColor(
            QPalette.WindowText, QColor("#e1ebfa" if self.dark_mode else "#243b5a")
        )
        palette.setColor(
            QPalette.Text, QColor("#e1ebfa" if self.dark_mode else "#243b5a")
        )
        palette.setColor(
            QPalette.Window, QColor("#14223b" if self.dark_mode else "#eff4fc")
        )
        palette.setColor(
            QPalette.Base, QColor("#14223b" if self.dark_mode else "#f6f9ff")
        )
        self.setPalette(palette)
        self.file_list.viewport().update()
        self.theme_btn.setText("Light mode" if self.dark_mode else "Dark mode")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    # ---------------- Encryption type ----------------
    def _update_encryption_summary(self, index):
        et = ENCRYPTION_TYPES[index]
        self.encryption_summary.setText(et["summary"])
        speed_label, stars = SPEED_RATING.get(et["name"], ("Unknown", ""))
        self.encryption_speed.setText(f"<b>Relative speed:</b> {speed_label}  {stars}")

    def show_encryption_type_info(self):
        et = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]
        dialog = EncryptionInfoDialog(self, et, self.show_comparison_dialog)
        dialog.exec()

    def show_comparison_dialog(self):
        dialog = ComparisonDialog(self)
        dialog.exec()

    # ---------------- Password helpers ----------------
    def toggle_password_visibility(self, state):
        mode = QLineEdit.Normal if state else QLineEdit.Password
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)

    def on_password_activity(self, text):
        self.update_strength(self.password_input.text())
        self.idle_timer.start()

    def auto_clear_passwords(self):
        if self.password_input.text() or self.confirm_input.text():
            self.password_input.clear()
            self.confirm_input.clear()
            self.log("Password fields auto-cleared after 5 minutes of inactivity.")

    def update_strength(self, text):
        self.strength_label.setVisible(bool(text))
        score, label, color = password_strength(text)
        self.strength_label.setText(label)
        self.strength_label.setStyleSheet(
            f"color: {color}; font-size: 12px; font-weight: 700;"
        )

    def fill_generated_password(self):
        pw = generate_password()
        self.show_pw_checkbox.setChecked(False)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.password_input.setText(pw)
        self.confirm_input.setText(pw)
        self.log(
            "Generated a new 20-character random password. Copy it somewhere safe now - it is not stored anywhere."
        )

    def verify_password(self):
        cvlt_files = [p for p in self.selected_paths if p.lower().endswith(".cvlt")]
        if not cvlt_files or not self.password_input.text():
            QMessageBox.information(
                self, "Check password", "Add a .cvlt file and enter its password first."
            )
            return
        target = Path(cvlt_files[0])
        secret, keyfile = self.password_input.text().encode("utf-8"), self.keyfile_path

        def verify(cancel):
            mixed = (
                secret_with_keyfile(secret, keyfile, cancel.is_set)
                if keyfile
                else secret
            )
            if cancel.is_set():
                raise Cancelled()
            detected = describe_encryption_type(target)
            ok = verify_password_quick(target, mixed)
            if cancel.is_set():
                raise Cancelled()
            return (
                f"[VERIFY] {target.name}: first chunk authenticated ({detected})."
                if ok
                else f"[VERIFY] {target.name}: wrong password/keyfile or damaged file."
            )

        self._start_utility("verify", verify)

    # ---------------- Output location ----------------
    def choose_output_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Choose output folder", self.last_dir
        )
        if path:
            self.output_dir = path
            self.output_input.setText(path)
            self.destination_note.setText(f"Saves to {path} · Existing files are kept")

    def reset_output_dir(self):
        self.output_dir = None
        self.output_input.setText("")
        self.destination_note.setText(
            "Saves beside the original · Existing files are kept"
        )

    def open_output_folder(self):
        if self.last_output_dir:
            open_in_file_manager(self.last_output_dir)

    # ---------------- Keyfile ----------------
    def choose_keyfile(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a keyfile", self.last_dir)
        if path:
            self.keyfile_path = path
            self.keyfile_input.setText(path)
            self.log(
                f"Keyfile set: {Path(path).name} - both this file AND the password will be required."
            )

    def generate_keyfile(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save new keyfile", "cryptvault.key", "Key files (*.key)"
        )
        if not path:
            return
        try:
            with open(path, "xb") as output:
                output.write(secrets.token_bytes(256))
        except OSError as exc:
            QMessageBox.warning(self, "Keyfile not saved", str(exc))
            return
        self.keyfile_path = path
        self.keyfile_input.setText(path)
        self.log(
            f"Generated a new keyfile at {path}. Keep this file safe and BACKED UP - "
            "losing it means anything encrypted with it becomes unrecoverable, even with the right password."
        )

    def clear_keyfile(self):
        self.keyfile_path = None
        self.keyfile_input.setText("")

    # ---------------- File selection ----------------
    def choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files", self.last_dir)
        if paths:
            self.last_dir = str(Path(paths[0]).parent)
            self.add_paths(paths)

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose a folder", self.last_dir)
        if path:
            self.last_dir = str(Path(path).parent)
            self.add_paths([path])

    def add_paths(self, paths):
        if self.total_tasks > self.completed_tasks:
            return
        paths = [str(Path(p).absolute()) for p in paths if Path(p).exists()]
        for p in paths:
            if p not in self.row_widgets:
                self.selected_paths.append(p)
                row_widget = FileRowWidget(p)
                item = QListWidgetItem()
                item.setSizeHint(row_widget.sizeHint())
                item.setToolTip(p)
                self.file_list.addItem(item)
                self.file_list.setItemWidget(item, row_widget)
                self.row_widgets[p] = row_widget
        self._update_queue()

    def _update_queue(self):
        count = len(self.selected_paths)
        self.queue_label.setText(f"{count} item{'s' if count != 1 else ''}")

    def remove_selected(self):
        if self.total_tasks > self.completed_tasks:
            return
        for item in self.file_list.selectedItems():
            row = self.file_list.row(item)
            path = self.selected_paths.pop(row)
            self.row_widgets.pop(path, None)
            self.file_list.takeItem(row)
        self._update_queue()

    def clear_list(self):
        if self.total_tasks > self.completed_tasks:
            return
        self.selected_paths = []
        self.row_widgets = {}
        self.file_list.clear()
        self._update_queue()

    def show_file_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        if not item:
            return
        row = self.file_list.row(item)
        path = self.selected_paths[row]

        menu = QMenu(self)
        encrypt_action = QAction("Encrypt This Item Only", self)
        encrypt_action.triggered.connect(lambda: self._run_single(path, "encrypt"))
        decrypt_action = QAction("Decrypt This Item Only", self)
        decrypt_action.triggered.connect(lambda: self._run_single(path, "decrypt"))
        menu.addAction(encrypt_action)
        menu.addAction(decrypt_action)
        menu.addSeparator()

        if Path(path).is_file():
            hash_action = QAction("Compute SHA-256", self)
            hash_action.triggered.connect(lambda: self._compute_hash(path))
            menu.addAction(hash_action)
            if path.lower().endswith(".cvlt"):
                info_action = QAction("Show Encryption Type Used", self)
                info_action.triggered.connect(
                    lambda: self._show_file_encryption_type(path)
                )
                menu.addAction(info_action)

        open_action = QAction("Open Containing Folder", self)
        open_action.triggered.connect(lambda: open_in_file_manager(Path(path).parent))
        remove_action = QAction("Remove From List", self)
        remove_action.triggered.connect(lambda: self._remove_row(row))
        menu.addAction(open_action)
        menu.addAction(remove_action)
        menu.exec(self.file_list.mapToGlobal(pos))

    def _compute_hash(self, path):
        def compute(cancel):
            digest = sha256_of_file(Path(path), cancel_check=cancel.is_set)
            return f"[SHA-256] {Path(path).name}: {digest}"

        self._start_utility("hash", compute)

    def _start_utility(self, kind, callback):
        if (
            self._closing
            or kind in self.utility_tasks
            or self.total_tasks > self.completed_tasks
        ):
            return
        task = UtilityTask(kind, callback)
        self.utility_tasks[kind] = task
        task.signals.finished.connect(self._utility_finished, Qt.QueuedConnection)
        self.btn_cancel.setEnabled(True)
        self.status_label.setText(
            "Checking password…" if kind == "verify" else "Calculating SHA-256…"
        )
        self.pool.start(task)

    @Slot(str, str)
    def _utility_finished(self, kind, message):
        self.utility_tasks.pop(kind, None)
        self.log(message)
        if not self.utility_tasks:
            self.btn_cancel.setEnabled(False)
            self.status_label.setText("Ready when you are")

    def _show_file_encryption_type(self, path):
        try:
            desc = describe_encryption_type(Path(path))
            self.log(f"[INFO] {Path(path).name} was encrypted with: {desc}")
        except Exception as e:
            self.log(f"[INFO] Could not read header of {path}: {e}")

    def _run_single(self, path, mode):
        if not self.password_input.text():
            QMessageBox.warning(self, "Missing password", "Enter a password first.")
            return
        if (
            mode == "encrypt"
            and self.password_input.text() != self.confirm_input.text()
        ):
            QMessageBox.warning(
                self, "Password mismatch", "Password and confirmation don't match."
            )
            return
        self._run_batch(mode, paths=[path])

    def _remove_row(self, row):
        if self.total_tasks > self.completed_tasks:
            return
        path = self.selected_paths.pop(row)
        self.row_widgets.pop(path, None)
        self.file_list.takeItem(row)
        self._update_queue()

    # ---------------- Logging ----------------
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(html.escape(f"[{timestamp}] {message}"))

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save log", "cryptvault_log.txt", "Text files (*.txt)"
        )
        if path:
            Path(path).write_text(self.log_box.toPlainText(), encoding="utf-8")
            self.log(f"Log saved to {path}")

    # ---------------- Batch control ----------------
    def _preset_name(self):
        return ["fast", "balanced", "paranoid"][self.security_combo.currentIndex()]

    def _validate(self, is_encrypt):
        if not self.selected_paths:
            QMessageBox.warning(
                self, "Missing input", "Add at least one file or folder."
            )
            return False
        if not self.password_input.text():
            QMessageBox.warning(self, "Missing password", "Enter a password.")
            return False
        if is_encrypt and self.password_input.text() != self.confirm_input.text():
            QMessageBox.warning(
                self, "Password mismatch", "Password and confirmation don't match."
            )
            return False
        return True

    def start_encrypt(self):
        if not self._validate(is_encrypt=True):
            return
        self._run_batch("encrypt")

    def start_decrypt(self):
        if not self._validate(is_encrypt=False):
            return
        self._run_batch("decrypt")

    def _set_running_state(self, running):
        self.btn_encrypt.setEnabled(not running)
        self.btn_decrypt.setEnabled(not running)
        self.btn_cancel.setEnabled(running)
        self.tabs.setTabEnabled(1, not running)
        self.tabs.setTabEnabled(2, not running)
        self.file_list.setAcceptDrops(not running)
        for button in self.picker_buttons:
            button.setEnabled(not running)
        self.password_input.setEnabled(not running)
        self.confirm_input.setEnabled(not running)
        self.status_label.setText(
            "Working on your files…" if running else "Ready when you are"
        )

    def _run_batch(self, mode, paths=None):
        if (
            self.utility_tasks
            or self._closing
            or self.total_tasks > self.completed_tasks
        ):
            return
        target_paths = list(paths if paths is not None else self.selected_paths)
        if not target_paths:
            return
        try:
            secret = self.password_input.text().encode("utf-8")
            if not secret:
                raise CryptoError("Enter a password first.")
            keyfile_signature = None
            if self.keyfile_path:
                validate_source(Path(self.keyfile_path))
                key_stat = Path(self.keyfile_path).stat()
                if key_stat.st_size == 0:
                    raise CryptoError("The selected keyfile is empty.")
                keyfile_signature = source_signature(key_stat)
            resolved = [Path(p).resolve() for p in target_paths]
            input_paths = set(resolved)
            if len(input_paths) != len(resolved):
                raise CryptoError("Remove duplicate input paths before starting.")
            for i, source in enumerate(resolved):
                validate_source(Path(target_paths[i]))
                if any(parent in input_paths for parent in source.parents):
                    raise CryptoError(
                        "Remove duplicate or overlapping input paths before starting."
                    )
                if self.shred_original.isChecked() and self.keyfile_path:
                    keyfile = Path(self.keyfile_path).resolve()
                    if source == keyfile or source in keyfile.parents:
                        raise CryptoError(
                            "Original deletion would destroy the selected keyfile."
                        )
        except Exception as exc:
            QMessageBox.warning(self, "Cannot start batch", str(exc))
            return
        self.cancel_event.clear()
        self.overall_bar.setValue(0)
        self.btn_open_output.setEnabled(False)
        self.total_tasks = len(target_paths)
        self.completed_tasks = 0
        self.batch_start_time = time.time()
        self._batch_failed = self._batch_cancelled = 0
        self.last_output_dir = None
        self._task_progress = {path: 0 for path in target_paths}
        self._progress_total = 0
        preset = self._preset_name()
        cipher_ids = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]["ciphers"]
        enc_name = ENCRYPTION_TYPES[self.encryption_combo.currentIndex()]["name"]
        keyfile_note = " + keyfile" if self.keyfile_path else ""

        for p in target_paths:
            row_widget = self.row_widgets.get(p)
            if row_widget:
                row_widget.set_progress(0)
                row_widget.status_label.setText("Starting...")

        if mode == "encrypt":
            self.log(
                f"Starting encrypt on {self.total_tasks} item(s) "
                f"[{enc_name}, {preset} password preset{keyfile_note}, "
                f"{self.pool.maxThreadCount()} parallel workers]..."
            )
        else:
            self.log(
                f"Starting decrypt on {self.total_tasks} item(s) "
                f"[encryption type auto-detected per file{keyfile_note}, "
                f"{self.pool.maxThreadCount()} parallel workers]..."
            )
        self._set_running_state(True)
        self.tabs.setCurrentIndex(0)

        for path in target_paths:
            task = CryptoTask(
                mode,
                path,
                secret,
                cipher_ids,
                preset,
                self.shred_original.isChecked(),
                self.output_dir,
                self.cancel_event,
                compress_folders=self.compress_folders.isChecked(),
            )
            task.keyfile_path = self.keyfile_path
            task.keyfile_signature = keyfile_signature
            self.active_tasks[path] = task
            task.signals.progress.connect(self.on_item_progress, Qt.QueuedConnection)
            task.signals.done.connect(self.on_item_done, Qt.QueuedConnection)
            task.signals.failed.connect(self.on_item_failed, Qt.QueuedConnection)
            task.signals.cancelled.connect(self.on_item_cancelled, Qt.QueuedConnection)
            self.pool.start(task)

    def cancel_batch(self):
        self.cancel_event.set()
        for task in self.utility_tasks.values():
            task.cancel_event.set()
        self.log("Cancel requested - in-progress items will stop shortly...")
        self.status_label.setText("Stopping safely…")

    def _update_progress(self, path, percent):
        previous = self._task_progress.get(path, 0)
        self._task_progress[path] = percent
        self._progress_total += percent - previous
        self.overall_bar.setValue(int(self._progress_total / max(self.total_tasks, 1)))

    @Slot(str, int)
    def on_item_progress(self, path, percent):
        self._update_progress(path, percent)

        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_progress(percent)

    def _item_finished(self, path, output_dir=None):
        self.active_tasks.pop(path, None)
        self._update_progress(path, 100)
        self.completed_tasks += 1
        if output_dir:
            self.last_output_dir = output_dir
        if self.completed_tasks >= self.total_tasks:
            total_time = time.time() - (self.batch_start_time or time.time())
            succeeded = (
                self.completed_tasks - self._batch_failed - self._batch_cancelled
            )
            summary = (
                f"{succeeded} completed · {self._batch_failed} failed · "
                f"{self._batch_cancelled} cancelled"
            )
            self.log(f"Batch finished in {total_time:.1f}s. {summary}")
            self._set_running_state(False)
            self.status_label.setText(summary)
            if self.last_output_dir:
                self.btn_open_output.setEnabled(True)
            if self.play_sound.isChecked():
                QApplication.beep()

    @Slot(str, str, float, object)
    def on_item_done(self, path, output_path, seconds, size):
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("✓ Done", done=True)
        speed = human_size(size / max(seconds, 0.01)) + "/s"
        self.log(
            f"[OK] {path} -> {output_path} ({human_size(size)}, {seconds:.1f}s, {speed})"
        )
        out_path = Path(output_path)
        out_dir = out_path if out_path.is_dir() else out_path.parent
        self._item_finished(path, output_dir=out_dir)

    @Slot(str, str)
    def on_item_failed(self, path, error_msg):
        self._batch_failed += 1
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("✗ Failed", failed=True)
        self.log(f"[FAIL] {path}: {error_msg}")
        self._item_finished(path)

    @Slot(str)
    def on_item_cancelled(self, path):
        self._batch_cancelled += 1
        row_widget = self.row_widgets.get(path)
        if row_widget:
            row_widget.set_status("⊘ Cancelled", cancelled=True)
        self.log(f"[CANCELLED] {path}")
        self._item_finished(path)


def _make_windows_dpi_aware():
    """Request DPI awareness before constructing Qt widgets on Windows."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        # PROCESS_PER_MONITOR_DPI_AWARE - correct, modern scaling behavior
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            # Older Windows fallback (pre-8.1) - basic system DPI awareness
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def configure_font(app):
    if not QFontDatabase.families() and sys.platform == "win32":
        font = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / "segoeui.ttf"
        if font.is_file():
            QFontDatabase.addApplicationFont(str(font))
    family = QFontDatabase.systemFont(QFontDatabase.GeneralFont).family()
    if "Segoe UI" in QFontDatabase.families():
        family = "Segoe UI"
    app.setFont(QFont(family, 10))


def main():
    _make_windows_dpi_aware()

    # Must be set before QApplication is constructed. On displays using a
    # fractional scale factor (125%, 150%, etc. - very common on laptops)
    # the default rounding policy can produce slightly-wrong-sized,
    # blurry-looking UI. PassThrough uses the exact scale factor Windows
    # reports instead of rounding it, which renders crisply everywhere.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    # Force Qt's built-in "Fusion" style instead of the native Windows
    # theme style. Fusion is compiled directly into Qt itself - it's not
    # a separate plugin DLL that a packaged exe can fail to bundle or
    # load correctly on a different machine.
    app.setStyle("Fusion")
    configure_font(app)
    window = MainWindow()
    window.show()
    return app.exec()
