import json
import time
from pathlib import Path

import click

from crow.banners import print_banner
from crow.core import PluginRegistry  
from crow.core.config import load_config
from crow.core.logger import logger


# -------------------- Helpers --------------------
def _instantiate_plugin(cls, config_obj, logger_obj):
    """
    بعض plugins تُنشأ بدون args (مثل dns/email عندك)
    وبعضها تتوقع (config, logger)
    """
    try:
        return cls(config_obj, logger_obj)
    except TypeError:
        return cls()


def _run_plugin(plugin_obj, target: str, **kwargs):
    """
    الافتراضي في CROW plugins: run() يرجع PluginOutput
    fallback: execute() لو كانت موجودة.
    """
    if hasattr(plugin_obj, "run") and callable(getattr(plugin_obj, "run")):
        return plugin_obj.run(target, **kwargs)
    if hasattr(plugin_obj, "execute") and callable(getattr(plugin_obj, "execute")):
        # بعض الأكواد القديمة ترجع list/dict
        return plugin_obj.execute(target)
    raise RuntimeError("Plugin has no run() or execute() method")


def _as_jsonable(obj):
    """تحويل المخرجات لأي شيء قابل للتخزين كـ JSON."""
   
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        return obj.dict()
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        return [_as_jsonable(x) for x in obj]
    
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def _save_json(path: str, data):
    with Path(path).open("w", encoding="utf-8") as f:
        json.dump(_as_jsonable(data), f, indent=2, ensure_ascii=False, default=str)


# -------------------- Click App --------------------
@click.group(invoke_without_command=True)
@click.pass_context
def app(ctx):
    """Crow Recon OSINT Framework"""
    print_banner()
    PluginRegistry.autoload()

    if ctx.invoked_subcommand is None:
        interactive_menu(ctx)


# ------------------------------------------------------
# 1) القائمة التفاعلية
# ------------------------------------------------------
def interactive_menu(ctx):
    click.echo("[CROW] Choose your mode:")
    click.echo("  [1] Automated scan (All passive + active)")
    click.echo("  [2] Manual scan (choose plugin(s))")
    click.echo("  [3] Exit")

    choice = click.prompt(
        "[CROW] Enter choice",
        type=click.Choice(["1", "2", "3"]),
        show_choices=False,
    )

    if choice == "1":
        target = click.prompt("→ Target (IP or Domain)")
        output = click.prompt("→ Output file", default="report.json")
        delay = click.prompt(
            "→ Delay between plugins (seconds)", default=1.0, type=float
        )
        ctx.invoke(auto, target=target, output=output, delay=delay)

    elif choice == "2":
        target = click.prompt("→ Target (IP or Domain)")
        plugins = click.prompt(
            "→ Plugin name(s) (comma separated) مثل: dns,whois,subdomain"
        )
        output = click.prompt(
            "→ Output file (optional)", default="", show_default=False
        )
        plist = [p.strip() for p in plugins.split(",") if p.strip()]
        ctx.invoke(scan, target=target, plugin=tuple(plist), output=(output or None))

    elif choice == "3":
        click.echo("Goodbye!")
        return


# ------------------------------------------------------
# 2) أمر تلقائي: شغّل كل الـ plugins
# ------------------------------------------------------
@app.command("auto")
@click.option("-t", "--target", required=True, help="Domain/IP to scan")
@click.option("-o", "--output", default="report.json", help="Output file")
@click.option(
    "-d", "--delay", default=1.0, type=float, help="Delay between plugins (seconds)"
)
def auto(target, output, delay):
    """Run all passive & active plugins against target."""
    config_obj = load_config()

    all_plugins = PluginRegistry.list_passive() + PluginRegistry.list_active()
    outputs = []

    for name in all_plugins:
        if name in PluginRegistry.list_passive():
            cls = PluginRegistry.get_passive(name)
        else:
            cls = PluginRegistry.get_active(name)

        if not cls:
            continue

        try:
            inst = _instantiate_plugin(cls, config_obj, logger)
            logger.info(f"Running plugin: {name}")
            out = _run_plugin(inst, target)
            outputs.append(_as_jsonable(out))
        except Exception as e:
            logger.error(f"Plugin {name} failed: {e}")
            outputs.append({"plugin": name, "results": [], "errors": [str(e)]})

        if delay:
            time.sleep(float(delay))

    _save_json(output, outputs)
    click.echo(f"✅ Report saved to: {output}")
    click.echo(f"📊 Summary: {len(outputs)} plugin outputs")


# ------------------------------------------------------
# 3) أمر يدوي: شغّل plugin واحد أو أكثر
#    ✅ يدعم: -p dns -p whois -p subdomain
#    ✅ أو:   -p dns,whois,subdomain
# ------------------------------------------------------
@app.command("scan")
@click.option("-t", "--target", required=True, help="Target domain/IP")
@click.option(
    "-p",
    "--plugin",
    required=True,
    multiple=True,
    help="Plugin name (repeatable) e.g: -p dns -p whois OR comma separated: -p dns,whois",
)
@click.option("-o", "--output", default=None, help="Output file (optional)")
def scan(target, plugin, output):
    """Run one or more plugins."""
    config_obj = load_config()

    # flatten comma-separated plugins + repeated plugins
    plugin_names = []
    for item in plugin:
        plugin_names.extend([x.strip() for x in item.split(",") if x.strip()])

    outputs = []

    for pname in plugin_names:
        cls = None
        if pname in PluginRegistry.list_passive():
            cls = PluginRegistry.get_passive(pname)
        elif pname in PluginRegistry.list_active():
            cls = PluginRegistry.get_active(pname)

        if not cls:
            outputs.append(
                {
                    "plugin": pname,
                    "results": [],
                    "errors": [f"Plugin '{pname}' not found"],
                }
            )
            continue

        try:
            inst = _instantiate_plugin(cls, config_obj, logger)
            out = _run_plugin(inst, target)
            outputs.append(_as_jsonable(out))
        except Exception as e:
            outputs.append({"plugin": pname, "results": [], "errors": [str(e)]})

    if output:
        _save_json(output, outputs)
        click.echo(f"✅ Saved to: {output}")
    else:
        click.echo(json.dumps(outputs, indent=2, ensure_ascii=False, default=str))


# ------------------------------------------------------
# 4) عرض الأدوات
# ------------------------------------------------------
@app.command("list-plugins")
def list_plugins():
    """List all loaded plugins."""
    click.echo("Passive plugins:")
    for k in PluginRegistry.list_passive():
        click.echo(f"  • {k}")

    click.echo("\nActive plugins:")
    for k in PluginRegistry.list_active():
        click.echo(f"  • {k}")

    click.echo("\nReporter plugins:")
    for k in PluginRegistry.list_reporters():
        click.echo(f"  • {k}")


# ------------------------------------------------------
if __name__ == "__main__":
    app()
