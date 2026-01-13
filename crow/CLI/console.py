"""
crow/CLI/console.py
"""

from __future__ import annotations

import cmd
import readline
import os
import sys
import json
import shlex
import contextlib
import io
import webbrowser
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, date

# CROW core
try:
    from crow.core import PluginRegistry, load_config, logger
    HAS_CROW = True
except Exception:
    HAS_CROW = False
    PluginRegistry = None  # type: ignore
    load_config = None  # type: ignore
    logger = None  # type: ignore

# Colors (optional)
try:
    from colorama import init, Fore, Style  # type: ignore
    init(autoreset=True)
except Exception:
    class DummyColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = DummyColor()

# Figlet (optional)
try:
    from pyfiglet import Figlet  # type: ignore
    HAS_FIGLET = True
except Exception:
    HAS_FIGLET = False
    Figlet = None  # type: ignore


class CrowConsole(cmd.Cmd):
    """
    CROW interactive console (MSF-like)
    """

    STATE_HOME = "HOME"
    STATE_MANUAL = "MANUAL"
    STATE_MODULE = "MODULE"

    def __init__(self, workspace: str = "default", version: str = "1.0.0"):
        super().__init__()
        self.workspace = workspace
        self.version = version

        # --- Resolve project root BEFORE banner ---
        self.project_root = self._find_project_root()
        self.reports_dir = self.project_root / "reports"
        self.auto_dir = self.reports_dir / "auto"
        self.manual_dir = self.reports_dir / "manual"
        self.auto_dir.mkdir(parents=True, exist_ok=True)
        self.manual_dir.mkdir(parents=True, exist_ok=True)

        self.state = self.STATE_HOME
        self.current_module: Optional[str] = None
        self.module_options: Dict[str, str] = {}
        self.results: List[Dict[str, Any]] = []

        # Manual ordering for numeric selection
        self.manual_order: List[str] = []

        self.prompt = f"{Fore.GREEN}crow > {Style.RESET_ALL}"
        self.intro = self._get_banner()
        self.history_file = os.path.expanduser(f"~/.crow_history_{workspace}")

        # Config
        self.config = load_config() if HAS_CROW and callable(load_config) else {}

        # Load plugins
        self.plugins = self._load_plugins()

        # History
        self._init_history()

    # ---------------- Project root ----------------

    def _find_project_root(self) -> Path:
        """
        Find project root by searching for pyproject.toml upwards.
        Fallback to current working dir.
        """
        try:
            here = Path(__file__).resolve()
            for p in [here.parent, *here.parents]:
                if (p / "pyproject.toml").exists():
                    return p
        except Exception:
            pass
        return Path.cwd().resolve()

    # ---------------- Banner ----------------

    def _render_logo(self) -> str:
        if HAS_FIGLET and Figlet is not None:
            try:
                f = Figlet(font="banner3-D")
                return f.renderText("CROW")
            except Exception:
                pass
        return "crow\n"

    def _get_banner(self) -> str:
        logo = self._render_logo()
        return (
            f"{Fore.CYAN}{logo}{Style.RESET_ALL}"
            f"{Fore.WHITE}Crow Recon OSINT Framework {self.version}{Style.RESET_ALL}\n"
            f"{Fore.WHITE}Workspace: {self.workspace}{Style.RESET_ALL}\n"
            f"{Fore.WHITE}Project: {str(self.project_root)}{Style.RESET_ALL}\n\n"
            f"{Fore.YELLOW}Type 'help' for available commands{Style.RESET_ALL}\n"
            f"{Fore.MAGENTA}Type 'exit' to quit{Style.RESET_ALL}\n\n"
            f"{Fore.CYAN}[1] Auto   - Run full framework against a target{Style.RESET_ALL}\n"
            f"{Fore.CYAN}[2] Manual - Choose tool by number and run{Style.RESET_ALL}\n"
        )

    # ---------------- History ----------------

    def _init_history(self):
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)

    def _save_history(self):
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass

    # ---------------- Logger helpers ----------------

    def _silence_logger_temporarily(self, level: str = "CRITICAL"):
        """
        Silence logs so only 'loading.....' appears.
        """
        if not HAS_CROW or logger is None:
            return
        try:
            logger.remove()
            logger.add(sys.stderr, level=level)
        except Exception:
            pass

    def _restore_logger_default(self):
        if not HAS_CROW or logger is None:
            return
        try:
            logger.remove()
            logger.add(
                sys.stderr,
                format="{time} | {level} | {name}:{function}:{line} - {message}",
                level="INFO",
                colorize=True,
            )
        except Exception:
            pass

    @contextlib.contextmanager
    def _quiet_run(self):
        """
        Suppress stdout/stderr and silence logger while running plugins.
        """
        self._silence_logger_temporarily("CRITICAL")
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                yield
        finally:
            self._restore_logger_default()

    # ---------------- JSON Safe ----------------

    def _json_safe(self, obj: Any) -> Any:
        """
        Convert non-JSON-serializable objects (datetime, bytes, Path, etc.).
        """
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
            return {str(k): self._json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [self._json_safe(x) for x in obj]
        # pydantic/dataclasses-like
        if hasattr(obj, "model_dump"):
            try:
                return self._json_safe(obj.model_dump())
            except Exception:
                pass
        if hasattr(obj, "__dict__"):
            try:
                return self._json_safe(vars(obj))
            except Exception:
                pass
        return str(obj)

    # ---------------- Plugin loading ----------------

    def _load_plugins(self) -> Dict[str, Any]:
        plugins: Dict[str, Any] = {}
        if not HAS_CROW or PluginRegistry is None:
            return plugins

        # silence autoload noise
        self._silence_logger_temporarily("CRITICAL")
        try:
            PluginRegistry.autoload()

            passive = PluginRegistry.list_passive()
            active = PluginRegistry.list_active()

            for name in passive:
                info = PluginRegistry.get_plugin_info(name) or {}
                info.setdefault("type", "passive")
                info.setdefault("description", "No description")
                info.setdefault("version", "1.0.0")
                plugins[name] = info

            for name in active:
                info = PluginRegistry.get_plugin_info(name) or {}
                info.setdefault("type", "active")
                info.setdefault("description", "No description")
                info.setdefault("version", "1.0.0")
                plugins[name] = info

            plugins = dict(sorted(plugins.items(), key=lambda kv: (kv[1].get("type", ""), kv[0])))

        except Exception as e:
            print(f"{Fore.RED}[!] Plugin autoload failed: {e}{Style.RESET_ALL}")
            plugins = {}
        finally:
            self._restore_logger_default()

        return plugins

    # ---------------- Helpers ----------------

    def _update_prompt(self):
        if self.current_module:
            self.prompt = f"{Fore.GREEN}crow({self.current_module}) > {Style.RESET_ALL}"
        else:
            self.prompt = f"{Fore.GREEN}crow > {Style.RESET_ALL}"

    def _auto_json_path(self) -> Path:
        return self.auto_dir / "report.json"

    def _auto_html_path(self) -> Path:
        return self.auto_dir / "report.html"

    def _manual_json_path(self, plugin_name: str) -> Path:
        return self.manual_dir / f"{plugin_name}.json"

    def _manual_html_path(self, plugin_name: str) -> Path:
        return self.manual_dir / f"{plugin_name}.html"

    def _open_in_browser(self, path: Path):
        try:
            webbrowser.open(path.resolve().as_uri())
        except Exception:
            pass

    def _run_plugin(self, plugin_name: str, target: str, **kwargs) -> Dict[str, Any]:
        info = self.plugins.get(plugin_name, {}) or {}
        ptype = info.get("type", "unknown")

        try:
            if ptype == "passive":
                inst = PluginRegistry.create_passive(plugin_name, self.config, logger)
                out = inst.run(target, **kwargs)
            elif ptype == "active":
                inst = PluginRegistry.create_active(plugin_name, self.config, logger)
                out = inst.run(target, **kwargs)
            else:
                return {
                    "status": "error",
                    "plugin": plugin_name,
                    "target": target,
                    "error": f"Unsupported plugin type: {ptype}",
                }

            payload = out.model_dump() if hasattr(out, "model_dump") else out
            payload = self._json_safe(payload)

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

    # ---------------- Report writers ----------------

    def _write_json(self, path: Path, payload: Dict[str, Any]):
        safe = self._json_safe(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False)

    def _write_html_report(self, path: Path, title: str, payload: Dict[str, Any]):
        """
        Single-page HTML report (RTL) with animated big CROW hero + clean layout.
        - No "Finding"
        - Summary card overlays Results (behind it)
        - Responsive / no ugly right overflow
        """
        safe = self._json_safe(payload)
        data_json = json.dumps(safe, ensure_ascii=False)

        html = f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.10);
      --border: rgba(255,255,255,0.10);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.65);
      --accent: #66f;
      --accent2: #00d4ff;
      --good: #39d98a;
      --bad: #ff5c5c;
      --shadow: 0 20px 60px rgba(0,0,0,0.45);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans Arabic", "Noto Sans", sans-serif;
      background: radial-gradient(1200px 700px at 80% 10%, rgba(102,102,255,0.22), transparent 60%),
                  radial-gradient(900px 600px at 10% 70%, rgba(0,212,255,0.18), transparent 55%),
                  var(--bg);
      color: var(--text);
      overflow-x: hidden;
    }}

    /* HERO (full first screen) */
    .hero {{
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 40px 18px;
      position: relative;
    }}
    .hero::before {{
      content: "";
      position: absolute;
      inset: -200px;
      background:
        radial-gradient(circle at 50% 50%, rgba(102,102,255,0.22), transparent 55%),
        radial-gradient(circle at 35% 60%, rgba(0,212,255,0.18), transparent 60%);
      filter: blur(40px);
      opacity: 0.8;
      animation: floatGlow 10s ease-in-out infinite;
    }}
    @keyframes floatGlow {{
      0%,100% {{ transform: translateY(0px); }}
      50% {{ transform: translateY(18px); }}
    }}

    .logoWrap {{
      position: relative;
      text-align: center;
      z-index: 2;
      max-width: 980px;
      width: 100%;
    }}

    .logo {{
      font-size: clamp(72px, 14vw, 160px);
      font-weight: 900;
      letter-spacing: 2px;
      margin: 0;
      line-height: 0.95;
      background: linear-gradient(90deg, #fff, rgba(255,255,255,0.55), #fff);
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      position: relative;
      display: inline-block;
      text-shadow: 0 0 40px rgba(102,102,255,0.35);
      animation: shimmer 2.8s ease-in-out infinite;
    }}
    @keyframes shimmer {{
      0% {{ filter: drop-shadow(0 0 0 rgba(102,102,255,0.0)); transform: translateY(0); }}
      50% {{ filter: drop-shadow(0 0 20px rgba(0,212,255,0.35)); transform: translateY(-6px); }}
      100% {{ filter: drop-shadow(0 0 0 rgba(102,102,255,0.0)); transform: translateY(0); }}
    }}

    .subtitle {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.7;
    }}

    .heroCard {{
      margin-top: 26px;
      display: inline-flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: center;
      padding: 14px 16px;
      border: 1px solid var(--border);
      background: var(--panel);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }}

    .pill {{
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.05);
      color: var(--text);
      font-size: 13px;
      white-space: nowrap;
    }}

    .btn {{
      cursor: pointer;
      user-select: none;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(102,102,255,0.35), rgba(0,212,255,0.22));
      color: #fff;
      font-weight: 700;
      transition: transform .15s ease, filter .15s ease;
    }}
    .btn:hover {{ transform: translateY(-2px); filter: brightness(1.1); }}

    /* CONTENT */
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 18px 80px;
    }}

    .sectionTitle {{
      margin: 0 0 14px;
      font-size: 18px;
      color: rgba(255,255,255,0.9);
    }}

    .layout {{
      position: relative;
      margin-top: 30px;
      padding-top: 10px;
    }}

    /* Results is the "background" */
    .results {{
      border: 1px solid var(--border);
      background: var(--panel);
      border-radius: 20px;
      padding: 18px;
      box-shadow: var(--shadow);
    }}

    /* Summary overlays results */
    .summary {{
      position: absolute;
      top: -22px;
      left: 18px; /* RTL: keep it visually nice; still left side overlay */
      width: min(420px, calc(100% - 36px));
      border: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(255,255,255,0.10), rgba(255,255,255,0.06));
      border-radius: 20px;
      padding: 16px;
      box-shadow: var(--shadow);
      z-index: 2;
      backdrop-filter: blur(8px);
    }}

    .kv {{
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 8px 12px;
      font-size: 13px;
      color: var(--muted);
    }}
    .kv b {{ color: var(--text); font-weight: 700; }}
    .kv .ok {{ color: var(--good); }}
    .kv .bad {{ color: var(--bad); }}

    .resultsInner {{
      padding-top: 130px; /* leave space for summary overlay */
      display: grid;
      gap: 14px;
    }}

    .card {{
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.04);
      border-radius: 18px;
      padding: 14px;
      overflow: hidden;
    }}
    .cardHeader {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 10px;
    }}
    .tag {{
      font-size: 12px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.05);
      color: var(--muted);
      white-space: nowrap;
    }}
    .cardTitle {{
      font-weight: 900;
      font-size: 15px;
      color: rgba(255,255,255,0.92);
      margin: 0;
    }}

    pre {{
      margin: 0;
      padding: 12px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(0,0,0,0.25);
      overflow: auto;
      direction: ltr;
      text-align: left;
      font-size: 12px;
      line-height: 1.6;
      color: rgba(255,255,255,0.88);
      max-width: 100%;
    }}

    .footer {{
      margin-top: 26px;
      color: var(--muted);
      font-size: 12px;
      text-align: center;
    }}

    @media (max-width: 720px) {{
      .summary {{
        position: static;
        width: 100%;
        margin-bottom: 14px;
      }}
      .resultsInner {{ padding-top: 0; }}
    }}
  </style>
</head>
<body>
  <section class="hero">
    <div class="logoWrap">
      <h1 class="logo">CROW</h1>
      <div class="subtitle">
       {title} 
      </div>
      <div class="heroCard">
        <span class="pill">Project: {str(self.project_root)}</span>
        <span class="pill">Workspace: {self.workspace}</span>
        <span class="pill" id="tsPill">Timestamp: —</span>
        <span class="btn" onclick="document.getElementById('report').scrollIntoView({{behavior:'smooth'}})">عرض التقرير</span>
      </div>
    </div>
  </section>

  <div class="container" id="report">
    <div class="layout">
      <div class="summary" id="summary">
        <div class="sectionTitle">Summary</div>
        <div class="kv" id="kv"></div>
      </div>

      <div class="results">
        <div class="sectionTitle">Results</div>
        <div class="resultsInner" id="results"></div>
      </div>
    </div>

    <div class="footer">Generated by CROW • {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  </div>

  <script>
    const DATA = {data_json};

    function safe(v) {{
      if (v === null || v === undefined) return "";
      if (typeof v === "object") return JSON.stringify(v, null, 2);
      return String(v);
    }}

    function buildSummary(data) {{
      const kv = document.getElementById("kv");
      kv.innerHTML = "";

      // Try common keys
      const status = data.status ?? (data.results ? "success" : "unknown");
      const target = data.target ?? data?.payload?.target ?? "";
      const ts = data.timestamp ?? data?.payload?.timestamp ?? "";

      document.getElementById("tsPill").textContent = "Timestamp: " + (ts || "—");

      const items = [
        ["Status", status],
        ["Target", target],
      ];

      // AUTO payload has results list
      if (data.results && Array.isArray(data.results)) {{
        items.push(["Plugins", data.results.length]);
      }}

      // MANUAL payload may have plugin
      if (data.plugin) items.push(["Plugin", data.plugin]);
      if (data.type) items.push(["Type", data.type]);

      // render
      for (const [k, v] of items) {{
        const kEl = document.createElement("div");
        kEl.innerHTML = "<b>" + k + "</b>";
        const vEl = document.createElement("div");
        let vv = safe(v);
        if (k === "Status") {{
          vEl.innerHTML = "<span class='" + (vv === "success" ? "ok" : "bad") + "'>" + vv + "</span>";
        }} else {{
          vEl.textContent = vv;
        }}
        kv.appendChild(kEl);
        kv.appendChild(vEl);
      }}
    }}

    function card(title, tag, obj) {{
      const wrap = document.createElement("div");
      wrap.className = "card";

      const h = document.createElement("div");
      h.className = "cardHeader";

      const t = document.createElement("h3");
      t.className = "cardTitle";
      t.textContent = title;

      const tg = document.createElement("span");
      tg.className = "tag";
      tg.textContent = tag;

      h.appendChild(t);
      h.appendChild(tg);

      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify(obj, null, 2);

      wrap.appendChild(h);
      wrap.appendChild(pre);
      return wrap;
    }}

    function buildResults(data) {{
      const root = document.getElementById("results");
      root.innerHTML = "";

      // AUTO report: show each plugin result cleanly
      if (data.results && Array.isArray(data.results)) {{
        for (const r of data.results) {{
          const title = (r.plugin ? r.plugin : "plugin");
          const tag = (r.status ? r.status : "result");
          root.appendChild(card(title, tag, r));
        }}
        return;
      }}

      // MANUAL: show the whole payload, and if output exists show it separately
      if (data.output) {{
        root.appendChild(card("Output", "payload", data.output));
      }}
      root.appendChild(card("Raw", "json", data));
    }}

    buildSummary(DATA);
    buildResults(DATA);
  </script>
</body>
</html>
"""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    # ---------------- Commands ----------------

    def do_help(self, arg):
        """
        help            Show help (all commands)
        help <command>  Show help for a command
        """
        arg = (arg or "").strip()

        commands = [
            ("help", "Show help (all commands)"),
            ("help <command>", "Show help for a command"),
            ("1", "Auto (run all plugins)"),
            ("2", "Manual (choose plugin by number)"),
            ("auto <target>", "Run auto directly"),
            ("manual", "Show manual tools list"),
            ("back", "Go back to HOME (from manual/module)"),
            ("exit", "Quit"),
        ]

        if arg:
            # try built-in docstring help
            fn = getattr(self, f"do_{arg}", None)
            if fn and fn.__doc__:
                print(fn.__doc__.strip())
            else:
                print(f"No detailed help for '{arg}'.")
            return

        # prettier output
        print("Commands:")
        for c, d in commands:
            print(f"  {c:<14} {d}")

    def do_auto(self, arg):
        """AUTO mode: auto [target]"""
        target = (arg or "").strip()
        if not target:
            try:
                target = input(f"{Fore.CYAN}Target (e.g., target.com): {Style.RESET_ALL}").strip()
            except KeyboardInterrupt:
                print()
                return

        if not target:
            print(f"{Fore.RED}[!] Target is required{Style.RESET_ALL}")
            return

        self.plugins = self._load_plugins()
        if not self.plugins:
            print(f"{Fore.RED}[!] No plugins loaded.{Style.RESET_ALL}")
            return

        print("loading.....")

        results: List[Dict[str, Any]] = []
        with self._quiet_run():
            for pname in self.plugins.keys():
                results.append(self._run_plugin(pname, target))

        payload = {
            "framework": "CROW",
            "version": self.version,
            "workspace": self.workspace,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }
        payload = self._json_safe(payload)

        json_path = self._auto_json_path()
        html_path = self._auto_html_path()
        self._write_json(json_path, payload)
        self._write_html_report(html_path, "AUTO Report", payload)

        self.results.append(payload)

        print(f"{Fore.GREEN}[+] AUTO saved JSON => {json_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] AUTO saved HTML => {html_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Open report: {html_path.resolve().as_uri()}{Style.RESET_ALL}")
        self._open_in_browser(html_path)

    def do_manual(self, arg):
        """MANUAL mode: manual"""
        self.state = self.STATE_MANUAL
        self.current_module = None
        self.module_options = {}
        self._update_prompt()

        self.plugins = self._load_plugins()
        self.manual_order = list(self.plugins.keys())

        print(f"{Fore.CYAN}[*] Tools / Plugins (Manual Mode){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'─' * 90}{Style.RESET_ALL}")

        if not self.plugins:
            print(f"{Fore.YELLOW}No plugins loaded.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'─' * 90}{Style.RESET_ALL}")
            return

        for i, name in enumerate(self.manual_order, start=1):
            info = self.plugins[name]
            desc = info.get("description", "No description")
            ptype = info.get("type", "unknown")
            print(f"[{i:02d}] {Fore.GREEN}{name:<20}{Style.RESET_ALL} [{ptype:<7}] - {desc}")

        print(f"{Fore.YELLOW}{'─' * 90}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Tip:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Or:{Style.RESET_ALL} back\n")

    def do_back(self, arg):
        """back: return to HOME"""
        self.current_module = None
        self.module_options = {}
        self.state = self.STATE_HOME
        self._update_prompt()
        print(self._get_banner())

    def do_exit(self, arg):
        """exit"""
        print(f"{Fore.YELLOW}[*] Exiting CROW console...{Style.RESET_ALL}")
        self._save_history()
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    # --- Key fix: default behaves by STATE ---
    def default(self, line):
        line = (line or "").strip()

        # HOME: 1/2 are shortcuts
        if self.state == self.STATE_HOME:
            if line == "1":
                self.do_auto("")
                return
            if line == "2":
                self.do_manual("")
                return
            if line.startswith("auto "):
                self.do_auto(line[len("auto "):].strip())
                return
            if line == "manual":
                self.do_manual("")
                return
            print(f"{Fore.RED}[!] Unknown command: {line}{Style.RESET_ALL}")
            return

        # MANUAL: numbers select plugins (fix the repeating list issue)
        if self.state == self.STATE_MANUAL:
            if line.lower() in ("back",):
                self.do_back("")
                return

            if line.isdigit():
                idx = int(line)
                if not self.manual_order:
                    self.manual_order = list(self.plugins.keys())

                if 1 <= idx <= len(self.manual_order):
                    plugin_name = self.manual_order[idx - 1]

                    try:
                        target = input(f"{Fore.CYAN}Target (e.g., target.com): {Style.RESET_ALL}").strip()
                    except KeyboardInterrupt:
                        print()
                        return

                    if not target:
                        print(f"{Fore.RED}[!] Target is required{Style.RESET_ALL}")
                        return

                    print("loading.....")

                    with self._quiet_run():
                        res = self._run_plugin(plugin_name, target)

                    # Save MANUAL report (overwrite)
                    json_path = self._manual_json_path(plugin_name)
                    html_path = self._manual_html_path(plugin_name)
                    self._write_json(json_path, res)
                    self._write_html_report(html_path, f"MANUAL Report — {plugin_name}", res)

                    self.results.append(res)

                    print(f"{Fore.GREEN}[+] MANUAL saved JSON => {json_path}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] MANUAL saved HTML => {html_path}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Open report: {html_path.resolve().as_uri()}{Style.RESET_ALL}")
                    self._open_in_browser(html_path)

                    return

                print(f"{Fore.RED}[!] Invalid selection. Choose 1-{len(self.manual_order)}{Style.RESET_ALL}")
                return

            print(f"{Fore.RED}[!] Unknown command in manual: {line}{Style.RESET_ALL}")
            return

        print(f"{Fore.RED}[!] Unknown command: {line}{Style.RESET_ALL}")

    def emptyline(self):
        pass


def start_console(workspace: str = "default"):
    console = None
    try:
        console = CrowConsole(workspace=workspace, version="1.0.0")
        console.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        if console:
            console._save_history()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    start_console()
