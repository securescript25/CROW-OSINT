"""
crow/CLI/console.py
"""

from __future__ import annotations

import cmd
import readline
import os
import sys
import json
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

    # ---------------- HTML helpers ----------------

    def _html_escape(self, s: Any) -> str:
        s = "" if s is None else str(s)
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _json_for_script(self, data_json: str) -> str:
        return data_json.replace("</", "<\\/")

    # ---------------- Plugin loading ----------------

    def _load_plugins(self) -> Dict[str, Any]:
        plugins: Dict[str, Any] = {}
        if not HAS_CROW or PluginRegistry is None:
            return plugins

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
        safe = self._json_safe(payload)
        data_json = json.dumps(safe, ensure_ascii=False)
        data_json = self._json_for_script(data_json)

        html = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>__TITLE__</title>
  <style>
    :root{
      --bg:#0b0f19;
      --panel:rgba(255,255,255,0.07);
      --border:rgba(255,255,255,0.14);
      --text:rgba(255,255,255,0.96);
      --muted:rgba(255,255,255,0.70);
      --good:#39d98a;
      --bad:#ff5c5c;
      --shadow:0 22px 70px rgba(0,0,0,0.55);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,"Noto Sans Arabic",sans-serif;
      background:
        radial-gradient(1200px 700px at 70% 15%, rgba(120,120,255,0.18), transparent 62%),
        radial-gradient(900px 600px at 15% 75%, rgba(0,212,255,0.14), transparent 58%),
        var(--bg);
      color:var(--text);
      overflow-x:hidden;
    }

    .hero{
      min-height:100vh;
      display:grid;
      place-items:center;
      padding:42px 18px;
      position:relative;
      perspective:1100px;
    }

    /* ✅ Comfort glow: less opacity + softer background */
    .hero::before{
      content:"";
      position:absolute;
      inset:-220px;
      background:
        radial-gradient(circle at 50% 50%, rgba(120,120,255,0.16), transparent 60%),
        radial-gradient(circle at 35% 60%, rgba(0,212,255,0.12), transparent 64%);
      filter: blur(58px);
      opacity:.75;
      animation: floatGlow 10s ease-in-out infinite;
    }

    @keyframes floatGlow{
      0%,100%{transform:translateY(0)}
      50%{transform:translateY(18px)}
    }

    .heroWrap{
      position:relative;
      z-index:2;
      text-align:center;
      width:100%;
      max-width:1100px;
      transform-style:preserve-3d;
    }

    /* LOGO: PURE WHITE + EYE-COMFORT GLOW */
    .heroLogo{
      font-size:clamp(78px, 15vw, 190px);
      font-weight:1000;
      margin:0;
      line-height:.92;
      letter-spacing:10px;
      position:relative;
      display:inline-block;

      --rx:0deg;
      --ry:0deg;
      --tz:0px;

      color:#ffffff !important;
      background:none !important;
      -webkit-text-fill-color:#ffffff !important;
      -webkit-text-stroke:1px rgba(255,255,255,0.22);
      text-rendering:geometricPrecision;
      -webkit-font-smoothing:antialiased;

      transform-style:preserve-3d;
      transform:perspective(1100px) rotateX(var(--rx)) rotateY(var(--ry)) translateZ(var(--tz));
      will-change:transform,filter;

      /* ✅ Reduced glow */
      filter:
        drop-shadow(0 10px 22px rgba(0,0,0,0.55))
        drop-shadow(0 0 34px rgba(255,255,255,0.12))
        drop-shadow(0 0 44px rgba(130,130,255,0.34))
        drop-shadow(0 0 26px rgba(0,212,255,0.22));

      animation:
        logoFloat 4.6s ease-in-out infinite,
        logoPulse 3.6s ease-in-out infinite;
    }

    /* ✅ Softer aura behind text */
    .heroLogo::before{
      content:"CROW";
      position:absolute;
      inset:0;
      z-index:-1;
      transform:translateZ(-60px);
      color:rgba(170,210,255,0.18);
      filter:blur(10px);
      opacity:.55;
      animation:auraBreath 3.4s ease-in-out infinite;
    }

    /* ✅ Reduce scan overlay */
    .heroLogo::after{
      content:"";
      position:absolute;
      inset:-34px -48px;
      pointer-events:none;
      background:
        linear-gradient(180deg, transparent 0%, rgba(255,255,255,0.06) 45%, transparent 72%),
        linear-gradient(90deg, transparent 0%, rgba(0,212,255,0.10) 48%, transparent 60%);
      mix-blend-mode:screen;
      opacity:.12;
      transform:translateZ(55px);
      animation:scanMove 2.6s linear infinite;
      border-radius:24px;
    }

    @keyframes logoFloat{
      0%,100%{transform:perspective(1100px) rotateX(var(--rx)) rotateY(var(--ry)) translateZ(var(--tz)) translateY(0)}
      50%{transform:perspective(1100px) rotateX(var(--rx)) rotateY(var(--ry)) translateZ(var(--tz)) translateY(-12px)}
    }

    /* ✅ Gentle pulse only */
    @keyframes logoPulse{
      0%,100%{
        filter:
          drop-shadow(0 10px 22px rgba(0,0,0,0.55))
          drop-shadow(0 0 30px rgba(255,255,255,0.10))
          drop-shadow(0 0 40px rgba(130,130,255,0.30))
          drop-shadow(0 0 24px rgba(0,212,255,0.20));
      }
      50%{
        filter:
          drop-shadow(0 12px 26px rgba(0,0,0,0.58))
          drop-shadow(0 0 42px rgba(255,255,255,0.14))
          drop-shadow(0 0 58px rgba(150,150,255,0.44))
          drop-shadow(0 0 32px rgba(0,212,255,0.28));
      }
    }

    @keyframes auraBreath{
      0%,100%{opacity:.45; transform:translateZ(-60px) scale(1)}
      50%{opacity:.70; transform:translateZ(-60px) scale(1.05)}
    }

    @keyframes scanMove{
      0%{transform:translateZ(55px) translateY(-48px)}
      100%{transform:translateZ(55px) translateY(48px)}
    }

    .heroSub{
      margin-top:14px;
      color:var(--muted);
      font-size:14px;
      transform:translateZ(20px);
    }

    .heroBar{
      margin:28px auto 0;
      display:flex;
      flex-direction:column;
      gap:12px;
      justify-content:center;
      align-items:center;
      padding:14px 16px;
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:18px;
      box-shadow:var(--shadow);
      backdrop-filter:blur(8px);
      transform:translateZ(10px);
    }
    .heroRow{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      justify-content:center;
      align-items:center;
      width:100%;
    }
    .pill{
      padding:10px 12px;
      border-radius:14px;
      border:1px solid var(--border);
      background:rgba(255,255,255,0.05);
      color:var(--text);
      font-size:13px;
      white-space:nowrap;
      max-width:100%;
      overflow:hidden;
      text-overflow:ellipsis;
      direction:ltr;
      text-align:left;
    }
    .btn{
      cursor:pointer;
      user-select:none;
      padding:12px 14px;
      border-radius:14px;
      border:1px solid var(--border);
      background:linear-gradient(135deg, rgba(102,102,255,0.42), rgba(0,212,255,0.26));
      color:#fff;
      font-weight:1000;
      letter-spacing:.3px;
      transition:transform .15s ease, filter .15s ease;
    }
    .btn:hover{transform:translateY(-2px);filter:brightness(1.06)}

    .wrap{max-width:1200px;margin:0 auto;padding:22px 14px 60px}
    .top{
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:14px;
      padding:16px;
      margin-bottom:16px;
      box-shadow:var(--shadow);
    }
    h2.pageTitle{margin:0 0 10px;font-size:18px}
    .kv{
      display:grid;
      grid-template-columns:160px 1fr;
      gap:8px 12px;
      font-size:13px;
      color:var(--muted);
    }
    .kv b{color:var(--text)}
    .ok{color:var(--good);font-weight:1000}
    .bad{color:var(--bad);font-weight:1000}

    .card{
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:14px;
      padding:14px;
      margin-bottom:14px;
      box-shadow:var(--shadow);
    }
    .cardHeader{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      flex-wrap:wrap;
      margin-bottom:10px;
    }
    .title{font-size:15px;font-weight:1000;margin:0}
    .tag{
      font-size:12px;
      padding:6px 10px;
      border:1px solid var(--border);
      border-radius:999px;
      color:var(--muted);
      direction:ltr;
    }

    pre{
      margin:12px 0 0;
      padding:14px;
      border-radius:12px;
      border:1px solid var(--border);
      background:rgba(0,0,0,0.26);
      overflow:auto;
      white-space:pre;
      font-size:12px;
      line-height:1.65;
      color:rgba(255,255,255,0.93);
      direction:ltr;
      text-align:left;
      max-height:560px;
    }

    .footer{margin-top:18px;color:var(--muted);font-size:12px;text-align:center}
    @media (max-width:700px){
      .kv{grid-template-columns:120px 1fr}
      .heroLogo{letter-spacing:6px}
    }
  </style>
</head>
<body>

  <section class="hero" id="hero">
    <div class="heroWrap" id="heroWrap">
      <h1 class="heroLogo" id="heroLogo">CROW</h1>
      <div class="heroSub">__TITLE__</div>

      <div class="heroBar">
        <div class="heroRow">
          <span class="pill" id="pillTs">Timestamp: —</span>
          <span class="pill">Workspace: __WORKSPACE__</span>
        </div>
        <div class="heroRow">
          <button class="btn" onclick="document.getElementById('report').scrollIntoView({behavior:'smooth'})">View Report</button>
        </div>
      </div>
    </div>
  </section>

  <div class="wrap" id="report">
    <div class="top">
      <h2 class="pageTitle">__TITLE__</h2>
      <div class="kv" id="summaryKV"></div>
    </div>

    <div id="cards"></div>

    <div class="footer">Generated by CROW • __NOW__</div>
  </div>

  <script>
    const DATA = __DATA_JSON__;

    function pretty(v){
      if (v === null || v === undefined) return "";
      if (typeof v === "string") return v;
      try { return JSON.stringify(v, null, 2); } catch(e){ return String(v); }
    }

    function addSummaryRow(k, v, cls=""){
      const root = document.getElementById("summaryKV");
      const kEl = document.createElement("div");
      kEl.innerHTML = "<b>" + k + "</b>";
      const vEl = document.createElement("div");
      if (cls) vEl.innerHTML = "<span class='" + cls + "'>" + v + "</span>";
      else vEl.textContent = v;
      root.appendChild(kEl);
      root.appendChild(vEl);
    }

    function buildSummary(data){
      const target = data.target ?? "-";
      const ts = data.timestamp ?? "-";

      const pill = document.getElementById("pillTs");
      if (pill) pill.textContent = "Timestamp: " + String(ts);

      let plugins = 0, ok = 0, bad = 0;

      if (Array.isArray(data.results)){
        plugins = data.results.length;
        for (const r of data.results){
          const st = String(r.status ?? "unknown").toLowerCase();
          if (st === "success") ok++; else bad++;
        }
      } else {
        plugins = 1;
        const st = String(data.status ?? "unknown").toLowerCase();
        if (st === "success") ok = 1; else bad = 1;
      }

      addSummaryRow("Target", String(target));
      addSummaryRow("Timestamp", String(ts));
      addSummaryRow("Plugins", String(plugins));
      addSummaryRow("Success", String(ok), "ok");
      addSummaryRow("Errors", String(bad), "bad");
    }

    function onMove(e){
      const hero = document.getElementById("hero");
      const logo = document.getElementById("heroLogo");
      if (!hero || !logo) return;

      const r = hero.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width;
      const y = (e.clientY - r.top) / r.height;

      const ry = (x - 0.5) * 26;
      const rx = (0.5 - y) * 20;
      const tz = 34;

      logo.style.setProperty("--rx", rx.toFixed(2) + "deg");
      logo.style.setProperty("--ry", ry.toFixed(2) + "deg");
      logo.style.setProperty("--tz", tz + "px");
    }

    function resetTilt(){
      const logo = document.getElementById("heroLogo");
      if (!logo) return;
      logo.style.setProperty("--rx", "0deg");
      logo.style.setProperty("--ry", "0deg");
      logo.style.setProperty("--tz", "0px");
    }

    (function(){
      const hero = document.getElementById("hero");
      if (!hero) return;
      hero.addEventListener("mousemove", onMove, {passive:true});
      hero.addEventListener("mouseleave", resetTilt, {passive:true});
      hero.addEventListener("touchend", resetTilt, {passive:true});
    })();

    function renderCard(r){
      const card = document.createElement("div");
      card.className = "card";

      const header = document.createElement("div");
      header.className = "cardHeader";

      const title = document.createElement("h3");
      title.className = "title";
      title.textContent = String(r.plugin ?? "plugin");

      const st = String(r.status ?? "unknown").toLowerCase();
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.innerHTML = "status: <span class='" + (st === "success" ? "ok" : "bad") + "'>" + st + "</span>";

      header.appendChild(title);
      header.appendChild(tag);
      card.appendChild(header);

      const pre = document.createElement("pre");
      pre.textContent = pretty(r.output);
      card.appendChild(pre);

      if (r.error){
        const pre2 = document.createElement("pre");
        pre2.textContent = pretty(r.error);
        card.appendChild(pre2);
      }

      return card;
    }

    function buildResults(data){
      const root = document.getElementById("cards");
      root.innerHTML = "";

      if (Array.isArray(data.results)){
        for (const r of data.results){
          root.appendChild(renderCard(r));
        }
        return;
      }

      root.appendChild(renderCard(data));
    }

    buildSummary(DATA);
    buildResults(DATA);
  </script>
</body>
</html>
"""
        html = html.replace("__TITLE__", self._html_escape(title))
        html = html.replace("__NOW__", self._html_escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        html = html.replace("__DATA_JSON__", data_json)
        html = html.replace("__WORKSPACE__", self._html_escape(self.workspace))

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
            fn = getattr(self, f"do_{arg}", None)
            if fn and fn.__doc__:
                print(fn.__doc__.strip())
            else:
                print(f"No detailed help for '{arg}'.")
            return

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

    def default(self, line):
        line = (line or "").strip()

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
