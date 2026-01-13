"""
crow/CLI/main.py
"""

import sys
import argparse
from typing import List, Optional

from .console import CrowConsole
from .parser import CommandParser

def main():
    """الدالة الرئيسية لتشغيل CLI"""
    parser = argparse.ArgumentParser(
        description="CROW Reconnaissance Framework - Command Line Interface",
        epilog="Example: crow scan -t google.com -p bhp"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # 1. أوامر المسح (Scan)
    scan_parser = subparsers.add_parser("scan", help="Run a scan")
    scan_parser.add_argument("-t", "--target", required=True, help="Target to scan")
    scan_parser.add_argument("-p", "--plugin", required=True, help="Plugin to use")
    scan_parser.add_argument("--ports", help="Ports to scan (e.g., 80,443 or 1-1000)")
    scan_parser.add_argument("--mode", help="Scan mode (portscan, banner, headers, all)")
    scan_parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds")
    scan_parser.add_argument("--output", help="Output file")
    
    # 2. أوامر القائمة (List)
    list_parser = subparsers.add_parser("list", help="List available items")
    list_parser.add_argument("type", choices=["plugins", "results", "sessions"], 
                           help="Type of items to list")
    
    # 3. أوامر العرض (Show)
    show_parser = subparsers.add_parser("show", help="Show detailed information")
    show_parser.add_argument("type", choices=["plugin", "result", "session"], 
                           help="Type of information to show")
    show_parser.add_argument("name", help="Name of the item")
    
    # 4. أوامر الواجهة التفاعلية (Console)
    console_parser = subparsers.add_parser("console", help="Start interactive console")
    console_parser.add_argument("--workspace", default="default", help="Workspace name")
    
    # 5. أوامر المساعدة (Help)
    help_parser = subparsers.add_parser("help", help="Show help")
    help_parser.add_argument("command", nargs="?", help="Command to get help for")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == "console":
            # تشغيل الواجهة التفاعلية
            console = CrowConsole(workspace=args.workspace)
            console.start()
        elif args.command == "scan":
            # تنفيذ المسح مباشرة
            from .commands import run_scan
            result = run_scan(
                target=args.target,
                plugin=args.plugin,
                ports=args.ports,
                mode=args.mode,
                timeout=args.timeout
            )
            
            if args.output:
                with open(args.output, 'w') as f:
                    import json
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"Results saved to {args.output}")
            else:
                import json
                print(json.dumps(result, indent=2, ensure_ascii=False))
                
        elif args.command == "list":
            from .commands import list_items
            items = list_items(args.type)
            for item in items:
                print(f"- {item}")
                
        elif args.command == "show":
            from .commands import show_item
            result = show_item(args.type, args.name)
            import json
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
        elif args.command == "help":
            if args.command:
                parser.parse_args([args.command, "--help"])
            else:
                parser.print_help()
                
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
