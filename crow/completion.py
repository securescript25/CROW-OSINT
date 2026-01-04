"""Tab completion لـ CROW – مثل msfconsole."""
import click

from crow.core import PluginRegistry


def enable_tab_completion():
    """نُفعّل completion لأسماء الأوامر والـ plugins."""

    # Completion لأسماء الأوامر
    @click.group(invoke_without_command=True)
    @click.pass_context
    def complete_app(ctx):
        pass

    # Completion لأسماء الـ plugins
    @complete_app.group()
    def complete_plugins():
        pass

    # Completion لأسماء الـ plugins داخل أوامر
    @complete_app.command()
    @click.argument(
        "plugin",
        type=click.Choice(PluginRegistry.list_passive() + PluginRegistry.list_active()),
    )
    def use(plugin):
        pass

    return complete_app
