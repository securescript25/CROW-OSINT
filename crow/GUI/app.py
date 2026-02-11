"""
crow/GUI/app.py
CROW GUI (PySide6)

- Modern UI
- Home shows logo.png
- App icon uses logo.ico
- Manual page: centered modern grid of tool buttons (click button opens tool)
- Domain page: larger centered card + long comfortable input
- HTML report identical to CLI (template extracted from crow/CLI/console.py)
- PDF feature inside HTML via browser print (window.print) with PRINT FIX (no scroll cut)
- Warn if target domain doesn't resolve (DNS)
- Auto open HTML report in Firefox (Kali-friendly)
- All UI messages are in English
"""

from __future__ import annotations

import sys
import io
import re
import json
import socket
import contextlib
import webbrowser
import subprocess
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QObject, Signal, QThread
from PySide6.QtGui import QFont, QPixmap, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QStackedWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QFrame,
    QTextEdit,
    QSizePolicy,
    QSpacerItem,
)

# --- CROW core ---
try:
    from crow.core import PluginRegistry, load_config, logger
    HAS_CROW = True
except Exception:
    HAS_CROW = False
    PluginRegistry = None  # type: ignore
    load_config = None  # type: ignore
    logger = None  # type: ignore


# ============================================================
# Paths
# ============================================================

def find_project_root() -> Path:
    try:
        here = Path(__file__).resolve()
        for p in [here.parent, *here.parents]:
            if (p / "pyproject.toml").exists():
                return p
    except Exception:
        pass
    return Path.cwd().resolve()


PROJECT_ROOT = find_project_root()

LOGO_PNG_PATH = PROJECT_ROOT / "crow" / "GUI" / "Image" / "logo.png"
LOGO_ICO_PATH = PROJECT_ROOT / "crow" / "GUI" / "Image" / "logo.ico"


def get_app_icon_path() -> Optional[Path]:
    if LOGO_ICO_PATH.exists():
        return LOGO_ICO_PATH
    if LOGO_PNG_PATH.exists():
        return LOGO_PNG_PATH
    return None


# ============================================================
# Helpers
# ============================================================

def json_safe(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="ignore")
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if hasattr(obj, "model_dump"):
        try:
            return json_safe(obj.model_dump())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        try:
            return json_safe(vars(obj))
        except Exception:
            pass
    return str(obj)


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    safe = json_safe(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, indent=2, ensure_ascii=False)


def _html_escape(s: Any) -> str:
    s = "" if s is None else str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _json_for_script(data_json: str) -> str:
    return data_json.replace("</", "<\\/")


_CLI_TEMPLATE_CACHE: Optional[str] = None


def _extract_cli_html_template() -> str:
    """
    Extract CLI HTML template from crow/CLI/console.py using a regex.
    """
    global _CLI_TEMPLATE_CACHE
    if _CLI_TEMPLATE_CACHE is not None:
        return _CLI_TEMPLATE_CACHE

    console_py = PROJECT_ROOT / "crow" / "CLI" / "console.py"
    if not console_py.exists():
        raise FileNotFoundError(f"CLI report source not found: {console_py}")

    text = console_py.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r'html\s*=\s*r?"""(.*?)"""', text, re.DOTALL)
    if not m:
        raise RuntimeError("Failed to extract CLI HTML template (pattern not found).")

    _CLI_TEMPLATE_CACHE = m.group(1)
    return _CLI_TEMPLATE_CACHE


def _inject_pdf_button_and_print_fix(html: str) -> str:
    if "@media print" not in html:
        html = html.replace(
            "</style>",
            """
    @media print{
      .no-print{display:none !important}

      pre{
        max-height: none !important;
        overflow: visible !important;
        white-space: pre-wrap !important;
        word-break: break-word !important;
      }

      .card{
        break-inside: avoid;
        page-break-inside: avoid;
      }

      *{animation:none !important; transition:none !important}
      body{overflow: visible !important}
    }
  </style>""",
            1,
        )

    needle = '<button class="btn" onclick="document.getElementById(\'report\').scrollIntoView({behavior:\'smooth\'})">View Report</button>'
    if needle in html:
        html = html.replace(
            needle,
            '<button class="btn no-print" onclick="document.getElementById(\'report\').scrollIntoView({behavior:\'smooth\'})">View Report</button>'
            '<button class="btn no-print" onclick="window.print()">Save as PDF</button>',
            1,
        )
    return html


def write_html_report_like_cli(path: Path, title: str, payload: Dict[str, Any], workspace: str) -> None:
    safe = json_safe(payload)
    data_json = json.dumps(safe, ensure_ascii=False)
    data_json = _json_for_script(data_json)

    template = _extract_cli_html_template()
    html = template
    html = html.replace("__TITLE__", _html_escape(title))
    html = html.replace("__NOW__", _html_escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    html = html.replace("__DATA_JSON__", data_json)
    html = html.replace("__WORKSPACE__", _html_escape(workspace))

    html = _inject_pdf_button_and_print_fix(html)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def open_report_in_firefox(path: Path) -> bool:
    try:
        uri = path.resolve().as_uri()
    except Exception:
        uri = "file://" + str(path)

    try:
        subprocess.Popen(["firefox", uri], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        try:
            return webbrowser.open(uri)
        except Exception:
            return False


def normalize_input_target(raw: str) -> tuple[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return "", ""
    parse_src = raw if "://" in raw else "http://" + raw
    p = urlparse(parse_src)
    host = p.hostname or ""
    return raw, host


def check_host_exists_dns(host: str) -> bool:
    if not host:
        return False
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


# ============================================================
# Runner Worker
# ============================================================

@dataclass
class RunRequest:
    mode: str
    target: str
    plugin_name: Optional[str] = None


class RunnerWorker(QObject):
    progress = Signal(str)
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, req: RunRequest, workspace: str):
        super().__init__()
        self.req = req
        self.workspace = workspace

        self.project_root = PROJECT_ROOT
        self.reports_dir = self.project_root / "reports"
        self.auto_dir = self.reports_dir / "auto"
        self.manual_dir = self.reports_dir / "manual"
        self.auto_dir.mkdir(parents=True, exist_ok=True)
        self.manual_dir.mkdir(parents=True, exist_ok=True)

        self.config = load_config() if HAS_CROW and callable(load_config) else {}

    def _silence_logger(self):
        try:
            if logger is not None:
                logger.remove()
                logger.add(sys.stderr, level="CRITICAL")
        except Exception:
            pass

    def _restore_logger(self):
        try:
            if logger is not None:
                logger.remove()
                logger.add(
                    sys.stderr,
                    format="{time} | {level} | {name}:{function}:{line} - {message}",
                    level="INFO",
                    colorize=True,
                )
        except Exception:
            pass

    def _run_plugin(self, plugin_name: str, target: str) -> Dict[str, Any]:
        info = PluginRegistry.get_plugin_info(plugin_name) or {}
        ptype = info.get("type", "unknown")

        try:
            if ptype == "passive":
                inst = PluginRegistry.create_passive(plugin_name, self.config, logger)
            elif ptype == "active":
                inst = PluginRegistry.create_active(plugin_name, self.config, logger)
            else:
                return {
                    "status": "error",
                    "plugin": plugin_name,
                    "type": ptype,
                    "target": target,
                    "timestamp": datetime.now().isoformat(),
                    "error": f"Unsupported plugin type: {ptype}",
                }

            out = inst.run(target)
            payload = out.model_dump() if hasattr(out, "model_dump") else out
            payload = json_safe(payload)

            return {
                "status": "success",
                "plugin": plugin_name,
                "type": ptype,
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "output": payload,
            }

        except Exception as e:
            return {
                "status": "error",
                "plugin": plugin_name,
                "type": ptype,
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
            }

    def run(self):
        if not HAS_CROW or PluginRegistry is None:
            self.failed.emit("CROW core not available (PluginRegistry import failed).")
            return

        self._silence_logger()

        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                PluginRegistry.autoload()

                if self.req.mode == "auto":
                    passive = list(PluginRegistry.list_passive())
                    active = list(PluginRegistry.list_active())
                    names = passive + active

                    self.progress.emit("loading.....")
                    results: List[Dict[str, Any]] = []
                    for name in names:
                        self.progress.emit(f"Running: {name}")
                        results.append(self._run_plugin(name, self.req.target))

                    payload = {
                        "framework": "CROW",
                        "version": "1.0.0",
                        "workspace": self.workspace,
                        "target": self.req.target,
                        "timestamp": datetime.now().isoformat(),
                        "results": results,
                    }

                    json_path = self.auto_dir / "report.json"
                    html_path = self.auto_dir / "report.html"

                    write_json(json_path, payload)
                    write_html_report_like_cli(html_path, "AUTO Report", payload, workspace=self.workspace)

                    payload["_paths"] = {"json": str(json_path), "html": str(html_path)}
                    self.finished.emit(json_safe(payload))
                    return

                if self.req.mode == "manual" and self.req.plugin_name:
                    self.progress.emit("loading.....")
                    self.progress.emit(f"Running: {self.req.plugin_name}")

                    res = self._run_plugin(self.req.plugin_name, self.req.target)

                    json_path = self.manual_dir / f"{self.req.plugin_name}.json"
                    html_path = self.manual_dir / f"{self.req.plugin_name}.html"

                    write_json(json_path, res)
                    write_html_report_like_cli(
                        html_path,
                        f"MANUAL Report — {self.req.plugin_name}",
                        res,
                        workspace=self.workspace,
                    )

                    res["_paths"] = {"json": str(json_path), "html": str(html_path)}
                    self.finished.emit(json_safe(res))
                    return

                self.failed.emit("Invalid request.")
        except Exception as e:
            self.failed.emit(str(e))
        finally:
            self._restore_logger()


# ============================================================
# UI
# ============================================================

APP_QSS = """
QMainWindow { background: #0b0f19; }
QWidget { color: rgba(255,255,255,0.92); font-family: 'Segoe UI', Arial; }

QFrame#Glass {
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.14);
  border-radius: 28px;
}

QLabel#Title {
  font-size: 22px;
  font-weight: 900;
  color: rgba(255,255,255,0.96);
}

QLabel#Sub {
  font-size: 13px;
  font-weight: 700;
  color: rgba(255,255,255,0.65);
}

QPushButton {
  border: 1px solid rgba(255,255,255,0.14);
  background: rgba(255,255,255,0.06);
  padding: 14px 18px;
  border-radius: 18px;
  font-size: 14px;
  font-weight: 800;
  min-height: 46px;
}
QPushButton:hover { background: rgba(255,255,255,0.10); }
QPushButton:pressed { background: rgba(255,255,255,0.13); }

QPushButton#Primary {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
    stop:0 rgba(120,120,255,0.70),
    stop:1 rgba(0,212,255,0.34)
  );
  border: 1px solid rgba(0,212,255,0.75);
  border-radius: 22px;
  min-height: 54px;
  padding: 14px 18px;
}
QPushButton#Primary:hover {
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
    stop:0 rgba(140,140,255,0.78),
    stop:1 rgba(0,212,255,0.40)
  );
}

QPushButton#ToolBtn {
  background: rgba(255,255,255,0.055);
  border: 1px solid rgba(255,255,255,0.16);
  border-radius: 20px;
  padding: 16px 18px;
  min-height: 64px;
  font-size: 14px;
  font-weight: 900;
}
QPushButton#ToolBtn:hover {
  background: rgba(255,255,255,0.10);
  border: 1px solid rgba(0,212,255,0.55);
}
QPushButton#ToolBtn:pressed {
  background: rgba(255,255,255,0.14);
}

QLineEdit {
  border: 1px solid rgba(255,255,255,0.14);
  background: rgba(255,255,255,0.06);
  padding: 16px 18px;
  border-radius: 22px;
  font-size: 14px;
  min-height: 56px;
}

QTextEdit {
  border: 1px solid rgba(255,255,255,0.14);
  background: rgba(0,0,0,0.25);
  border-radius: 18px;
  padding: 10px;
}
"""


class HomePage(QWidget):
    auto_clicked = Signal()
    manual_clicked = Signal()

    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(48, 36, 48, 28)
        outer.setSpacing(18)
        outer.addStretch(1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        pix = QPixmap(str(LOGO_PNG_PATH))
        if not pix.isNull():
            logo.setPixmap(pix.scaled(320, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo.setText("CROW")
            f = QFont()
            f.setPointSize(48)
            f.setBold(True)
            logo.setFont(f)

        outer.addWidget(logo)

        glass = QFrame()
        glass.setObjectName("Glass")
        gl = QVBoxLayout(glass)
        gl.setContentsMargins(28, 22, 28, 22)
        gl.setSpacing(12)

        title = QLabel("CROW Recon OSINT Framework")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)

        sub = QLabel("Choose a mode to start")
        sub.setObjectName("Sub")
        sub.setAlignment(Qt.AlignCenter)

        btn_auto = QPushButton("Auto")
        btn_auto.setObjectName("Primary")
        btn_manual = QPushButton("Manual")

        btn_auto.clicked.connect(self.auto_clicked.emit)
        btn_manual.clicked.connect(self.manual_clicked.emit)

        gl.addWidget(title)
        gl.addWidget(sub)
        gl.addSpacing(8)
        gl.addWidget(btn_auto)
        gl.addWidget(btn_manual)

        outer.addWidget(glass, alignment=Qt.AlignHCenter)
        outer.addStretch(2)


class DomainPage(QWidget):
    back_clicked = Signal()
    run_clicked = Signal(str)

    def __init__(self):
        super().__init__()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(60, 46, 60, 34)
        outer.setSpacing(18)

        outer.addStretch(1)

        glass = QFrame()
        glass.setObjectName("Glass")
        glass.setMaximumWidth(900)  # ✅ bigger, nicer card
        gl = QVBoxLayout(glass)
        gl.setContentsMargins(34, 28, 34, 26)
        gl.setSpacing(14)

        self.title = QLabel("Enter Domain")
        self.title.setObjectName("Title")
        self.title.setAlignment(Qt.AlignCenter)

        self.sub = QLabel("Example: example.com  or  https://example.com")
        self.sub.setObjectName("Sub")
        self.sub.setAlignment(Qt.AlignCenter)

        # ✅ Long comfortable input
        self.input = QLineEdit()
        self.input.setPlaceholderText("URL / Domain")
        self.input.setMinimumWidth(720)
        self.input.setMaximumWidth(720)
        self.input.setClearButtonEnabled(True)

        # ✅ nicer wide button
        self.run_btn = QPushButton("Run")
        self.run_btn.setObjectName("Primary")
        self.run_btn.setMinimumWidth(240)
        self.run_btn.setMaximumWidth(240)

        gl.addWidget(self.title)
        gl.addWidget(self.sub)
        gl.addSpacing(8)
        gl.addWidget(self.input, alignment=Qt.AlignHCenter)
        gl.addSpacing(10)
        gl.addWidget(self.run_btn, alignment=Qt.AlignHCenter)

        outer.addWidget(glass, alignment=Qt.AlignHCenter)
        outer.addStretch(2)

        bottom = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.setMaximumWidth(140)
        bottom.addWidget(self.back_btn, alignment=Qt.AlignLeft)
        bottom.addStretch(1)
        outer.addLayout(bottom)

        self.back_btn.clicked.connect(self.back_clicked.emit)
        self.run_btn.clicked.connect(self._on_run)
        self.input.returnPressed.connect(self._on_run)

    def set_title(self, t: str):
        self.title.setText(t)

    def set_sub(self, s: str):
        self.sub.setText(s)

    def _on_run(self):
        target = (self.input.text() or "").strip()
        if not target:
            QMessageBox.warning(self, "Missing target", "Please enter a domain/URL.")
            return
        self.run_clicked.emit(target)


class ManualPage(QWidget):
    back_clicked = Signal()
    plugin_clicked = Signal(str)

    def __init__(self):
        super().__init__()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(48, 36, 48, 28)
        outer.setSpacing(14)

        head = QFrame()
        head.setObjectName("Glass")
        hl = QVBoxLayout(head)
        hl.setContentsMargins(28, 18, 28, 18)
        hl.setSpacing(8)

        title = QLabel("Manual Mode")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)

        sub = QLabel("Click a tool to continue")
        sub.setObjectName("Sub")
        sub.setAlignment(Qt.AlignCenter)

        hl.addWidget(title)
        hl.addWidget(sub)
        outer.addWidget(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        self.grid_root = QWidget()
        self.grid_root_layout = QVBoxLayout(self.grid_root)
        self.grid_root_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_root_layout.setSpacing(0)

        self.center_wrap = QWidget()
        self.center_layout = QVBoxLayout(self.center_wrap)
        self.center_layout.setContentsMargins(0, 22, 0, 22)
        self.center_layout.setSpacing(0)
        self.center_layout.setAlignment(Qt.AlignTop | Qt.AlignHCenter)

        self.grid_container = QWidget()
        self.grid_container.setMaximumWidth(860)
        self.grid = QGridLayout(self.grid_container)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(14)

        self.center_layout.addWidget(self.grid_container, alignment=Qt.AlignHCenter)
        self.grid_root_layout.addWidget(self.center_wrap)

        scroll.setWidget(self.grid_root)
        outer.addWidget(scroll, 1)

        bottom = QHBoxLayout()
        self.back_btn = QPushButton("Back")
        self.back_btn.setMaximumWidth(140)
        bottom.addWidget(self.back_btn, alignment=Qt.AlignLeft)
        bottom.addStretch(1)
        outer.addLayout(bottom)

        self.back_btn.clicked.connect(self.back_clicked.emit)

    def set_plugins(self, plugins: Dict[str, Dict[str, Any]]):
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        names = list(plugins.keys())
        if not names:
            empty = QLabel("No plugins loaded.")
            empty.setObjectName("Sub")
            empty.setAlignment(Qt.AlignCenter)
            self.grid.addWidget(empty, 0, 0, 1, 1)
            return

        cols = 3
        r = c = 0
        for name in names:
            info = plugins.get(name, {}) or {}
            ptype = info.get("type", "unknown")
            desc = info.get("description", "No description")

            btn = QPushButton(f"{name}\n[{ptype}]")
            btn.setObjectName("ToolBtn")
            btn.setToolTip(desc)
            btn.setMinimumWidth(240)
            btn.clicked.connect(lambda _, pname=name: self.plugin_clicked.emit(pname))

            self.grid.addWidget(btn, r, c)

            c += 1
            if c >= cols:
                c = 0
                r += 1


class MainWindow(QMainWindow):
    def __init__(self, workspace: str = "default"):
        super().__init__()
        self.setWindowTitle("CROW")
        self.setMinimumSize(980, 620)

        icon_path = get_app_icon_path()
        if icon_path is not None:
            self.setWindowIcon(QIcon(str(icon_path)))

        self.workspace = workspace

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.home = HomePage()
        self.domain = DomainPage()
        self.manual = ManualPage()

        self.stack.addWidget(self.home)
        self.stack.addWidget(self.domain)
        self.stack.addWidget(self.manual)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(170)
        self.statusBar().setSizeGripEnabled(False)

        sbw = QWidget()
        sbl = QHBoxLayout(sbw)
        sbl.setContentsMargins(0, 0, 0, 0)
        sbl.addWidget(self.log)
        self.statusBar().addPermanentWidget(sbw, 1)

        self.home.auto_clicked.connect(self._go_auto)
        self.home.manual_clicked.connect(self._go_manual)

        self.domain.back_clicked.connect(self._go_home)
        self.domain.run_clicked.connect(self._domain_run_clicked)

        self.manual.back_clicked.connect(self._go_home)
        self.manual.plugin_clicked.connect(self._manual_choose_plugin)

        self.plugins_cache: Dict[str, Dict[str, Any]] = {}
        self._reload_plugins()

        self._domain_mode: str = "auto"
        self._domain_plugin: Optional[str] = None

    def _append_log(self, msg: str):
        self.log.append(msg)

    def _reload_plugins(self):
        if not HAS_CROW or PluginRegistry is None:
            self.plugins_cache = {}
            return
        try:
            PluginRegistry.autoload()
            all_plugins: Dict[str, Dict[str, Any]] = {}

            for n in PluginRegistry.list_passive():
                info = PluginRegistry.get_plugin_info(n) or {}
                info.setdefault("type", "passive")
                info.setdefault("description", "No description")
                all_plugins[n] = info

            for n in PluginRegistry.list_active():
                info = PluginRegistry.get_plugin_info(n) or {}
                info.setdefault("type", "active")
                info.setdefault("description", "No description")
                all_plugins[n] = info

            self.plugins_cache = dict(sorted(all_plugins.items(), key=lambda kv: (kv[1].get("type", ""), kv[0])))

        except Exception as e:
            self.plugins_cache = {}
            self._append_log(f"[Plugin load error] {e}")

    def _go_home(self):
        self.stack.setCurrentIndex(0)

    def _go_auto(self):
        self._domain_mode = "auto"
        self._domain_plugin = None
        self.domain.set_title("Enter Domain")
        self.domain.set_sub("Example: example.com  or  https://example.com")
        self.stack.setCurrentIndex(1)

    def _go_manual(self):
        self._reload_plugins()
        self.manual.set_plugins(self.plugins_cache)
        self.stack.setCurrentIndex(2)

    def _validate_target_or_warn(self, target_raw: str) -> Optional[str]:
        target, host = normalize_input_target(target_raw)
        if not target or not host:
            QMessageBox.warning(self, "Invalid target", "Please enter a valid domain/URL.")
            return None
        if not check_host_exists_dns(host):
            QMessageBox.warning(
                self,
                "Target not found",
                "The website/domain does not exist or cannot be resolved via DNS.\n\n"
                "Please verify the domain name or check your network/DNS settings.",
            )
            return None
        return target

    def _domain_run_clicked(self, target_raw: str):
        target = self._validate_target_or_warn(target_raw)
        if not target:
            return

        if self._domain_mode == "auto":
            self._start_worker(RunRequest(mode="auto", target=target))
            return

        if self._domain_mode == "manual" and self._domain_plugin:
            self._start_worker(RunRequest(mode="manual", target=target, plugin_name=self._domain_plugin))
            return

        QMessageBox.warning(self, "Invalid state", "No action selected.")

    def _manual_choose_plugin(self, plugin_name: str):
        self._domain_mode = "manual"
        self._domain_plugin = plugin_name
        self.domain.set_title(f"Enter Domain — {plugin_name}")
        self.domain.set_sub("Enter target then click Run (Manual).")
        self.stack.setCurrentIndex(1)

    def _start_worker(self, req: RunRequest):
        self._append_log("loading.....")
        self.setEnabled(False)

        self.thread = QThread()
        self.worker = RunnerWorker(req=req, workspace=self.workspace)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._append_log)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self._on_finished)

        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def _on_failed(self, err: str):
        self.setEnabled(True)
        self._append_log(f"[ERROR] {err}")
        QMessageBox.critical(self, "Run failed", err)

    def _on_finished(self, payload: dict):
        self.setEnabled(True)

        paths = payload.get("_paths") or {}
        html_path = paths.get("html") or ""
        json_path = paths.get("json") or ""

        self._append_log("[DONE] Report saved.")
        if json_path:
            self._append_log(f"JSON: {json_path}")
        if html_path:
            self._append_log(f"HTML: {html_path}")

        if html_path:
            ok = open_report_in_firefox(Path(html_path))
            if not ok:
                self._append_log("[WARN] Could not open Firefox automatically. Open HTML manually.")

        msg = "Completed ✅\n\n"
        if html_path:
            msg += f"HTML: {html_path}\n"
        if json_path:
            msg += f"JSON: {json_path}\n"
        msg += "\nIn the report, click: Save as PDF (or press Ctrl+P) then choose Save to PDF.\n"
        msg += "Tip: Enable 'Print backgrounds' in the print dialog if you want the same colors."

        QMessageBox.information(self, "CROW", msg)


def run_gui(workspace: str = "default"):
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_QSS)

    icon_path = get_app_icon_path()
    if icon_path is not None:
        app.setWindowIcon(QIcon(str(icon_path)))

    w = MainWindow(workspace=workspace)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
