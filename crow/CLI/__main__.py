"""
crow/CLI/main.py
"""

import sys
import argparse

def main():
    """الدالة الرئيسية لتشغيل CLI"""
    parser = argparse.ArgumentParser(
        description="CROW Reconnaissance Framework",
        epilog="""
Examples:
  crow scan -t google.com -p bhp
  crow console
  crow list plugins
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands",
        metavar="COMMAND"
    )
    
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a reconnaissance scan"
    )
    scan_parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target to scan (domain, IP, or URL)"
    )
    scan_parser.add_argument(
        "-p", "--plugin",
        required=True,
        help="Plugin to use (e.g., bhp, active_robots)"
    )
    scan_parser.add_argument(
        "--ports",
        help="Ports to scan (e.g., 80,443 or 1-1000)"
    )
    scan_parser.add_argument(
        "--mode",
        choices=["portscan", "banner", "headers", "all"],
        default="all",
        help="Scan mode"
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds"
    )
    scan_parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Number of threads"
    )
    scan_parser.add_argument(
        "--output",
        help="Output file (JSON format)"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    list_parser = subparsers.add_parser(
        "list",
        help="List available items"
    )
    list_parser.add_argument(
        "type",
        choices=["plugins", "targets", "results"],
        help="Type of items to list"
    )
    
    info_parser = subparsers.add_parser(
        "info",
        help="Show information about a plugin"
    )
    info_parser.add_argument(
        "plugin",
        help="Plugin name"
    )
    
    console_parser = subparsers.add_parser(
        "console",
        help="Start interactive console (MSFconsole-style)"
    )
    console_parser.add_argument(
        "--workspace",
        default="default",
        help="Workspace name"
    )
    
    help_parser = subparsers.add_parser(
        "help",
        help="Show help information"
    )
    help_parser.add_argument(
        "command",
        nargs="?",
        help="Command to get help for"
    )
    
    if len(sys.argv) == 1:
        from .console import start_console
        start_console()
        return
    
    args = parser.parse_args()
    
    try:
        if args.command == "console":
            from .console import start_console
            start_console(workspace=args.workspace)
            
        elif args.command == "scan":
            from .commands import run_scan
            result = run_scan(
                target=args.target,
                plugin=args.plugin,
                ports=args.ports,
                mode=args.mode,
                timeout=args.timeout,
                threads=args.threads,
                verbose=args.verbose
            )
            
            if args.output:
                import json
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"Results saved to: {args.output}")
            else:
                from .utils import display_results
                display_results(result)
                
        elif args.command == "list":
            from .commands import list_items
            items = list_items(args.type)
            if items:
                for item in items:
                    print(f"• {item}")
            else:
                print(f"No {args.type} found")
                
        elif args.command == "info":
            from .commands import show_plugin_info
            info = show_plugin_info(args.plugin)
            if info:
                import json
                print(json.dumps(info, indent=2, ensure_ascii=False))
            else:
                print(f"Plugin '{args.plugin}' not found")
                
        elif args.command == "help":
            if args.command:
                parser.parse_args([args.command, "--help"])
            else:
                parser.print_help()
                
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
