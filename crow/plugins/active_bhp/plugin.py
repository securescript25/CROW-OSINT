"""
CYBERSCAN ULTIMATE - Nmap-Style Scanner for CROW Framework
Modified Version with GOD MODE Enabled
Version: 4.0.0 | Codename: "PUBLIC_SCANNER"
"""

from __future__ import annotations
import ipaddress
import socket
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple
import requests
requests.packages.urllib3.disable_warnings()

from crow.core.bases import ActivePlugin
from crow.core.models import PluginOutput


class UltimateScanner(ActivePlugin):
    """
    ULTIMATE SCANNER - Modified for CROW Framework
    Complete scanning solution with GOD MODE enabled by default
    """
    
    name = "ultimate_scanner"
    description = "Nmap-style scanner with full public scanning capabilities"
    version = "4.0.0"
    
    def __init__(self, config=None, logger=None):
        try:
            super().__init__(config, logger)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass
        
        self.config = config or {}
        self.logger = logger
        
        # 🔥 GOD MODE ENABLED BY DEFAULT
        self.GOD_MODE = True
        self.PUBLIC_SCAN = True
        self.UNLIMITED = True
        
        # Performance settings
        self.max_threads = 1000
        self.timeout = 2.0
        self.retries = 2
    
    def _cfg_get(self, key: str, default: Any = None) -> Any:
        """Get config value"""
        if not self.config:
            return default
        try:
            return self.config.get(key, default)
        except:
            return default
    
    def _log(self, level: str, msg: str):
        """Logging function"""
        if self.logger:
            log_func = getattr(self.logger, level, None)
            if callable(log_func):
                try:
                    log_func(msg)
                except:
                    print(f"[{level.upper()}] {msg}")
        else:
            print(f"[{level.upper()}] {msg}")
    
    # 🔥 THE KEY MODIFICATION - PUBLIC SCANNING ENABLED
    def _authorization_ok(self, ip: str) -> bool:
        """
        ⚡⚡⚡ MODIFIED FUNCTION - ALLOWS ALL SCANS ⚡⚡⚡
        This function now returns True for ANY target
        """
        # GOD MODE - No restrictions at all
        if self.GOD_MODE:
            self._log("warning", f"⚡ GOD MODE: Scanning {ip} - UNRESTRICTED")
            return True
        
        # PUBLIC SCAN enabled
        if self.PUBLIC_SCAN:
            self._log("info", f"🔓 Public scan allowed for {ip}")
            return True
        
        # Fallback - still allow everything
        return True
    
    def _resolve_target(self, target: str) -> Tuple[str, List[str]]:
        """Resolve target to IP addresses"""
        try:
            # Try as IP first
            ipaddress.ip_address(target)
            return target, [target]
        except:
            # Try DNS resolution
            try:
                ips = []
                infos = socket.getaddrinfo(target, None)
                for info in infos:
                    ip = info[4][0]
                    if ip not in ips:
                        ips.append(ip)
                if ips:
                    return ips[0], ips
            except:
                pass
            
            # If all fails, return target as-is
            return target, [target]
    
    def _parse_ports(self, ports_spec: str) -> List[int]:
        """Parse port specification"""
        if not ports_spec:
            # Default common ports
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
                    5985, 5986, 6379, 8080, 8443, 8888, 9200, 9300]
        
        ports = set()
        parts = [p.strip() for p in ports_spec.split(',') if p.strip()]
        
        for part in parts:
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    for port in range(start, end + 1):
                        if 1 <= port <= 65535:
                            ports.add(port)
                except:
                    continue
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except:
                    continue
        
        return sorted(ports)
    
    def _tcp_connect(self, ip: str, port: int, timeout: float = None) -> Tuple[bool, float]:
        """TCP Connect Scan"""
        timeout = timeout or self.timeout
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            elapsed = time.time() - start_time
            sock.close()
            
            return (result == 0), elapsed
        except:
            return False, time.time() - start_time
    
    def _grab_banner(self, ip: str, port: int, timeout: float = None) -> str:
        """Grab banner from service"""
        timeout = timeout or self.timeout
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try to read banner
            time.sleep(0.1)
            sock.setblocking(0)
            data = b""
            
            start = time.time()
            while time.time() - start < 0.5:
                try:
                    chunk = sock.recv(1024)
                    if chunk:
                        data += chunk
                    else:
                        break
                except:
                    break
            
            sock.close()
            
            if data:
                # Try different encodings
                for encoding in ['utf-8', 'latin-1', 'cp1256']:
                    try:
                        return data.decode(encoding, errors='ignore').strip()
                    except:
                        continue
                return str(data)[:200]
                
        except:
            pass
        
        return ""
    
    def _analyze_http(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze HTTP/HTTPS service"""
        schemes = ["https", "http"] if port in [443, 8443] else ["http", "https"]
        
        for scheme in schemes:
            try:
                url = f"{scheme}://{ip}:{port}/"
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                
                return {
                    "status_code": response.status_code,
                    "server": response.headers.get('Server', ''),
                    "content_type": response.headers.get('Content-Type', ''),
                    "title": self._extract_title(response.text),
                    "headers": dict(response.headers)
                }
            except:
                continue
        
        return {}
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1)[:100] if match else ""
    
    def _detect_service(self, port: int, banner: str = "") -> str:
        """Detect service from port and banner"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-proxy", 8443: "https-alt",
            9200: "elasticsearch", 27017: "mongodb"
        }
        
        service = service_map.get(port, f"unknown/{port}")
        
        # Refine with banner
        if banner:
            banner_lower = banner.lower()
            if 'apache' in banner_lower:
                service = "apache"
            elif 'nginx' in banner_lower:
                service = "nginx"
            elif 'iis' in banner_lower:
                service = "iis"
            elif 'openssh' in banner_lower:
                service = "openssh"
        
        return service
    
    # 🔥 MAIN EXECUTION METHOD
    def execute(self, target: str) -> List[Dict[str, Any]]:
        """Main scan execution - MODIFIED FOR PUBLIC SCANNING"""
        start_time = time.time()
        
        # Resolve target
        try:
            primary_ip, all_ips = self._resolve_target(target)
            self._log("info", f"Target: {target} -> {primary_ip}")
        except Exception as e:
            self._log("error", f"Failed to resolve {target}: {e}")
            return []
        
        # 🔥 KEY CHANGE: NO AUTHORIZATION CHECK - ALLOW EVERYTHING
        self._log("warning", f"⚡ PUBLIC SCAN ENABLED for {primary_ip}")
        self._log("warning", "⚡ GOD MODE ACTIVE - No restrictions")
        
        # Get ports to scan
        ports_spec = self._cfg_get("active.ports", "1-1000")
        ports = self._parse_ports(ports_spec)
        
        self._log("info", f"Scanning {len(ports)} ports on {primary_ip}")
        
        # Perform port scan
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._tcp_connect, primary_ip, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, response_time = future.result()
                    if is_open:
                        open_ports.append(port)
                        self._log("info", f"  [+] {port}/tcp OPEN ({response_time:.3f}s)")
                except Exception as e:
                    self._log("debug", f"  [-] Port {port} error: {e}")
        
        open_ports.sort()
        
        # Collect detailed information
        results = []
        
        # Add summary
        results.append({
            "type": "SCAN_SUMMARY",
            "target": target,
            "ip": primary_ip,
            "all_ips": all_ips,
            "total_ports": len(ports),
            "open_ports": len(open_ports),
            "open_port_list": open_ports,
            "scan_duration": round(time.time() - start_time, 2),
            "scan_mode": "GOD_MODE",
            "scanner_version": self.version
        })
        
        # Detailed port information
        for port in open_ports:
            port_info = {
                "type": "PORT_DETAIL",
                "target": target,
                "ip": primary_ip,
                "port": port,
                "protocol": "tcp",
                "state": "open"
            }
            
            # Get banner
            banner = self._grab_banner(primary_ip, port)
            if banner:
                port_info["banner"] = banner[:500]
            
            # Detect service
            service = self._detect_service(port, banner)
            port_info["service"] = service
            
            # HTTP analysis for web ports
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                http_info = self._analyze_http(primary_ip, port)
                if http_info:
                    port_info["http_info"] = http_info
            
            results.append(port_info)
        
        self._log("success", f"✅ Scan completed in {time.time() - start_time:.2f}s")
        self._log("success", f"🎯 Found {len(open_ports)} open ports")
        
        return results
    
    def run(self, target: str, **kwargs) -> PluginOutput:
        """CROW framework integration"""
        output = PluginOutput(plugin=self.name)
        
        try:
            output.results = self.execute(target)
            output.metadata = {
                "scanner": self.name,
                "version": self.version,
                "target": target,
                "scan_mode": "GOD_MODE"
            }
        except Exception as e:
            error_msg = f"Scan failed: {e}"
            self._log("error", error_msg)
            output.errors.append(error_msg)
        
        return output
    
    # 🔥 CONTROL METHODS
    def enable_god_mode(self, enable: bool = True):
        """Enable/disable GOD MODE"""
        self.GOD_MODE = enable
        status = "ENABLED" if enable else "DISABLED"
        self._log("warning", f"⚡ GOD MODE {status}")
        return self
    
    def quick_scan(self, target: str) -> List[Dict[str, Any]]:
        """Quick scan of common ports"""
        self.config['active.ports'] = "21,22,23,25,53,80,110,143,443,445,3389,8080,8443"
        return self.execute(target)
    
    def full_scan(self, target: str) -> List[Dict[str, Any]]:
        """Full scan of all ports"""
        self.config['active.ports'] = "1-65535"
        return self.execute(target)