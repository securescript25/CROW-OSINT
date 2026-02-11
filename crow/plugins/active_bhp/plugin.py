"""
/plugins/active_bhp/plugin.py - Black Hat Python Cybernetic Reconnaissance Plugin
"""

from __future__ import annotations

import json
import random
import re
import socket
import ssl
import time
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
from enum import Enum

import requests


from crow.core.bases import ActivePlugin
from crow.core.logger import logger as default_logger
from crow.core.models import PluginOutput


# ====================== ENUMS ======================

class PortState(str, Enum):
    UNKNOWN = "unknown"
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    ERROR = "error"


class DisplayFilter(str, Enum):
    ALL = "all"
    OPEN_ONLY = "open_only"
    OPEN_CLOSED = "open_closed"
    OPEN_FILTERED = "open_filtered"
    NONE = "none"  


# ====================== MODELS ======================

@dataclass
class PortScanResult:
   
    plugin: str
    port: int
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    reason: Optional[str] = None
    latency: Optional[float] = None
    scan_method: Optional[str] = None
    should_display: bool = True  
    
    def is_displayable(self, 
                      show_closed: bool = False,
                      show_filtered: bool = False,
                      show_errors: bool = False,
                      min_port: int = 1,
                      max_port: int = 65535) -> bool:
        """
        تحديد إذا كان يجب عرض هذه النتيجة بناءً على عوامل التصفية
        """
        if not (min_port <= self.port <= max_port):
            return False
        
        if self.state == PortState.OPEN:
            return True
        
        if self.state == PortState.CLOSED and not show_closed:
            return False
        
        if self.state in [PortState.FILTERED, PortState.OPEN_FILTERED] and not show_filtered:
            return False
        
        if self.state == PortState.ERROR and not show_errors:
            return False
        
        return True


@dataclass
class BannerInfo:
    plugin: str
    service: str
    raw_banner: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    cert_info: Optional[Dict[str, Any]] = None
    service_details: Optional[Dict[str, Any]] = None


@dataclass
class HeaderAnalysis:
    plugin: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    security_score: int = 0
    missing_security_headers: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    server_info: Optional[Dict[str, Any]] = None
    cookie_analysis: Optional[Dict[str, Any]] = None
    redirect_chain: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ScanStatistics:
    total_scanned: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    error_count: int = 0
    hidden_count: int = 0  
    hidden_details: Dict[str, int] = field(default_factory=dict)  
    scan_duration: float = 0.0
    display_count: int = 0 


@dataclass
class FilterConfig:
    """إعدادات التصفية"""
    show_closed: bool = False
    show_filtered: bool = False
    show_errors: bool = False
    min_port: int = 1
    max_port: int = 65535
    display_filter: DisplayFilter = DisplayFilter.OPEN_ONLY


# ====================== MAIN PLUGIN ======================

class bhp(ActivePlugin):
    """
    Black Hat Python Active Reconnaissance Plugin
    بلوقين متطور للمسح الشامل مع تحليل متقدم + نظام تصفية المنافذ
    """

    name = "bhp"
    description = "Black Hat Python - Advanced Active Reconnaissance with Port Filtering"
    version = "3.0.0"  
       SERVICE_DB = {
        # TCP Services
        20: ("FTP Data", "ftp"),
        21: ("FTP Control", "ftp"),
        22: ("SSH", "ssh"),
        23: ("Telnet", "telnet"),
        25: ("SMTP", "smtp"),
        53: ("DNS", "dns"),
        80: ("HTTP", "http"),
        110: ("POP3", "pop3"),
        143: ("IMAP", "imap"),
        443: ("HTTPS", "https"),
        445: ("SMB", "smb"),
        465: ("SMTPS", "smtp"),
        587: ("SMTP Submission", "smtp"),
        993: ("IMAPS", "imap"),
        995: ("POP3S", "pop3"),
        1433: ("MSSQL", "database"),
        1521: ("Oracle DB", "database"),
        3306: ("MySQL", "database"),
        3389: ("RDP", "remote"),
        5432: ("PostgreSQL", "database"),
        5900: ("VNC", "remote"),
        6379: ("Redis", "database"),
        8080: ("HTTP Proxy", "http"),
        8443: ("HTTPS Alt", "https"),
        27017: ("MongoDB", "database"),
        28017: ("MongoDB HTTP", "http"),
        
        # UDP Services
        53: ("DNS", "dns"),
        67: ("DHCP Server", "dhcp"),
        68: ("DHCP Client", "dhcp"),
        69: ("TFTP", "tftp"),
        123: ("NTP", "ntp"),
        137: ("NetBIOS", "netbios"),
        138: ("NetBIOS", "netbios"),
        139: ("NetBIOS", "netbios"),
        161: ("SNMP", "snmp"),
        162: ("SNMP Trap", "snmp"),
        500: ("IPSec/IKE", "vpn"),
        514: ("Syslog", "logging"),
        520: ("RIP", "routing"),
        1900: ("UPnP", "discovery"),
        5353: ("mDNS", "dns"),
        4789: ("VXLAN", "tunneling"),
    }

    def __init__(self, config=None, logger_obj=None):
        self.config = config
        self.logger = logger_obj or default_logger

        self.timeout = self._cfg_get("timeout", 3)
        self.max_workers = self._cfg_get("max_workers", 100)
        self.user_agent = self._cfg_get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        
        self.scan_delay = self._cfg_get("scan_delay", 0.05)
        self.stealth_mode = self._cfg_get("stealth_mode", False)
        self.max_ports_per_scan = self._cfg_get("max_ports_per_scan", 1000)
        
        self.default_show_closed = self._cfg_get("show_closed", False)
        self.default_show_filtered = self._cfg_get("show_filtered", False)
        self.default_show_errors = self._cfg_get("show_errors", False)
        
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-XSS-Protection",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ]

    # -------------------- PUBLIC ENTRY WITH FILTERING --------------------

    def run(self, target: str, port: int = None, **kwargs) -> PluginOutput:
        """
        
        kwargs الجديدة:
          - show_closed: bool = False     # عرض المنافذ المغلقة
          - show_filtered: bool = False   # عرض المنافذ المفلترة
          - show_errors: bool = False     # عرض الأخطاء
          - min_port: int = 1            # أقل منفذ
          - max_port: int = 65535        # أعلى منفذ
          - display_filter: str = "open_only"  # all|open_only|open_closed|open_filtered|none
          
        كلمات دلالية جديدة للاستخدام السريع:
          - only_open: bool = True       # فقط المنافذ المفتوحة (اختصار)
          - verbose: bool = False        # عرض كل شيء
        """
        filter_config = self._parse_filter_parameters(kwargs)
        
        mode = (kwargs.get("mode") or "all").lower()
        protocol = (kwargs.get("protocol") or "tcp").lower()
        scan_method = kwargs.get("scan_method", "connect")
        custom_timeout = kwargs.get("timeout")
        
        if custom_timeout:
            self.timeout = float(custom_timeout)
        
        ports_input = kwargs.get("ports")
        if ports_input:
            raw_ports = self._parse_ports_input(ports_input)
            ports = [p for p in raw_ports if filter_config.min_port <= p <= filter_config.max_port]
            if len(ports) < len(raw_ports):
                self.logger.info(f"[bhp] Ports filtered: {len(raw_ports)} -> {len(ports)} "
                               f"(range: {filter_config.min_port}-{filter_config.max_port})")
        elif mode == "udp":
            ports = self._get_default_udp_ports()
            ports = [p for p in ports if filter_config.min_port <= p <= filter_config.max_port]
        else:
            ports = self._get_default_tcp_ports()
            ports = [p for p in ports if filter_config.min_port <= p <= filter_config.max_port]
        
        if len(ports) > self.max_ports_per_scan:
            self.logger.warning(f"[bhp] Reducing ports from {len(ports)} to {self.max_ports_per_scan}")
            ports = ports[:self.max_ports_per_scan]
        
        ip, all_ips = self._resolve_target(target)
        if not ip:
            return PluginOutput(
                plugin=self.name,
                results=[],
                errors=[f"Failed to resolve target: {target}"]
            )
        
        self.logger.info(f"[bhp] Scanning {target} ({ip}) - {len(ports)} ports, "
                        f"filters: closed={filter_config.show_closed}, "
                        f"filtered={filter_config.show_filtered}")
        
        results: List[Any] = []
        errors: List[str] = []
        scan_stats = ScanStatistics()
        
        try:
            start_time = time.time()
            
            # === MODE: PORTSCAN or ALL ===
            if mode in ("portscan", "all", "udp"):
                if protocol in ("tcp", "both"):
                    tcp_results, tcp_stats = self._advanced_port_scan_with_filters(
                        target, ip, ports, "tcp", scan_method, filter_config
                    )
                    scan_stats = self._merge_statistics(scan_stats, tcp_stats)
                    
                    filtered_tcp = self._filter_port_results(tcp_results, filter_config)
                    results.extend([self._to_dict_with_filters(x, filter_config) for x in filtered_tcp])
                
                if protocol in ("udp", "both"):
                    udp_results, udp_stats = self._advanced_udp_scan_with_filters(
                        target, ip, ports, filter_config
                    )
                    scan_stats = self._merge_statistics(scan_stats, udp_stats)
                    
                    filtered_udp = self._filter_port_results(udp_results, filter_config)
                    results.extend([self._to_dict_with_filters(x, filter_config) for x in filtered_udp])
            
            # === MODE: BANNER or ALL (if ports open) ===
            if mode in ("banner", "all"):
                open_ports = []
                for item in results:
                    if isinstance(item, dict) and item.get("state") == PortState.OPEN:
                        port_num = item.get("port")
                        if port_num:
                            open_ports.append(port_num)
                
                if open_ports:
                    self.logger.info(f"[bhp] Banner grabbing on {len(open_ports)} open ports")
                    banner_results = self._advanced_banner_grab(target, ip, open_ports)
                    results.extend([self._to_dict(x) for x in banner_results])
                elif mode == "banner":
                    self.logger.info("[bhp] Quick scan for banner grabbing")
                    quick_scan, _ = self._quick_port_scan_with_filters(
                        target, ip, ports[:50], filter_config
                    )
                    quick_open = [p.port for p in quick_scan if p.state == PortState.OPEN]
                    if quick_open:
                        banner_results = self._advanced_banner_grab(target, ip, quick_open)
                        results.extend([self._to_dict(x) for x in banner_results])
            
            # === MODE: HEADERS or ALL ===
            if mode in ("headers", "all"):
                self.logger.info("[bhp] Advanced HTTP header analysis")
                header_results = self._advanced_header_analysis(target, ip)
                results.extend([self._to_dict(x) for x in header_results])
            
            scan_stats.scan_duration = time.time() - start_time
            
        except Exception as e:
            error_msg = f"Plugin execution failed: {str(e)}"
            self.logger.error(f"[bhp] {error_msg}")
            errors.append(error_msg)
        
        if results and mode == "all":
            results.append(self._generate_enhanced_intelligence_report(
                target, ip, results, scan_stats, filter_config
            ))
        
        results.insert(0, self._create_filter_summary(scan_stats, filter_config))
        
        return PluginOutput(
            plugin=self.name,
            results=results,
            errors=errors
        )

    # ====================== FILTERING SYSTEM ======================

    def _parse_filter_parameters(self, kwargs: Dict) -> FilterConfig:
        """تحليل معاملات التصفية"""
        only_open = kwargs.get("only_open", False)
        verbose = kwargs.get("verbose", False)
        
        if only_open:
            return FilterConfig(
                show_closed=False,
                show_filtered=False,
                show_errors=False,
                display_filter=DisplayFilter.OPEN_ONLY
            )
        elif verbose:
            return FilterConfig(
                show_closed=True,
                show_filtered=True,
                show_errors=True,
                display_filter=DisplayFilter.ALL
            )
        
        show_closed = kwargs.get("show_closed", self.default_show_closed)
        show_filtered = kwargs.get("show_filtered", self.default_show_filtered)
        show_errors = kwargs.get("show_errors", self.default_show_errors)
        min_port = kwargs.get("min_port", 1)
        max_port = kwargs.get("max_port", 65535)
        
        if show_closed and show_filtered and show_errors:
            display_filter = DisplayFilter.ALL
        elif show_closed and not show_filtered:
            display_filter = DisplayFilter.OPEN_CLOSED
        elif show_filtered and not show_closed:
            display_filter = DisplayFilter.OPEN_FILTERED
        elif not show_closed and not show_filtered and not show_errors:
            display_filter = DisplayFilter.OPEN_ONLY
        else:
            display_filter = DisplayFilter.NONE
        
        return FilterConfig(
            show_closed=show_closed,
            show_filtered=show_filtered,
            show_errors=show_errors,
            min_port=min_port,
            max_port=max_port,
            display_filter=display_filter
        )

    def _filter_port_results(self, 
                           results: List[PortScanResult], 
                           filters: FilterConfig) -> List[PortScanResult]:
        filtered = []
        
        for result in results:
            if result.is_displayable(
                show_closed=filters.show_closed,
                show_filtered=filters.show_filtered,
                show_errors=filters.show_errors,
                min_port=filters.min_port,
                max_port=filters.max_port
            ):
                filtered.append(result)
        
        return filtered

    def _to_dict_with_filters(self, 
                            obj: Any, 
                            filters: FilterConfig) -> Any:
        if isinstance(obj, PortScanResult):
            if not obj.is_displayable(
                show_closed=filters.show_closed,
                show_filtered=filters.show_filtered,
                show_errors=filters.show_errors,
                min_port=filters.min_port,
                max_port=filters.max_port
            ):
                return None  
        
        return self._to_dict(obj)

    # ====================== ENHANCED PORT SCANNING ======================

    def _advanced_port_scan_with_filters(self, 
                                       hostname: str, 
                                       ip: str, 
                                       ports: List[int], 
                                       protocol: str, 
                                       method: str,
                                       filters: FilterConfig) -> Tuple[List[PortScanResult], ScanStatistics]:
        """مسح متقدم مع إحصائيات التصفية"""
        results: List[PortScanResult] = []
        stats = ScanStatistics()
        stats.total_scanned = len(ports)
        
        workers = min(self.max_workers, max(10, len(ports) // 10))
        
        self.logger.info(f"[bhp] Advanced {protocol.upper()} scan with filtering, {workers} workers")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {}
            
            for port in ports:
                if not (filters.min_port <= port <= filters.max_port):
                    continue
                
                if protocol == "tcp":
                    future = executor.submit(
                        self._scan_tcp_port_with_stats, ip, port, method, stats
                    )
                else:  # udp
                    future = executor.submit(
                        self._scan_udp_port_with_stats, hostname, ip, port, stats
                    )
                
                future_to_port[future] = port
                
                if self.stealth_mode and len(future_to_port) % 10 == 0:
                    time.sleep(self.scan_delay)
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    error_result = PortScanResult(
                        plugin=self.name,
                        port=port,
                        protocol=protocol,
                        state=PortState.ERROR,
                        reason=str(e),
                        scan_method=method
                    )
                    results.append(error_result)
                    stats.error_count += 1
        
        self._update_display_stats(results, stats, filters)
        
        return results, stats

    def _scan_tcp_port_with_stats(self, 
                                 ip: str, 
                                 port: int, 
                                 method: str,
                                 stats: ScanStatistics) -> Optional[PortScanResult]:
        """مسح منفذ TCP مع تحديث الإحصائيات"""
        start_time = time.time()
        
        try:
            result = self._scan_tcp_port(ip, port, method)
            result.latency = time.time() - start_time
            
            if result.state == PortState.OPEN:
                stats.open_count += 1
            elif result.state == PortState.CLOSED:
                stats.closed_count += 1
            elif result.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
                stats.filtered_count += 1
            elif result.state == PortState.ERROR:
                stats.error_count += 1
            
            return result
        
        except Exception as e:
            stats.error_count += 1
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="tcp",
                state=PortState.ERROR,
                reason=str(e),
                latency=time.time() - start_time,
                scan_method=method
            )

    def _scan_udp_port_with_stats(self, 
                                 hostname: str, 
                                 ip: str, 
                                 port: int,
                                 stats: ScanStatistics) -> PortScanResult:
        result = self._smart_udp_probe(hostname, ip, port)
        
        if result.state == PortState.OPEN:
            stats.open_count += 1
        elif result.state == PortState.CLOSED:
            stats.closed_count += 1
        elif result.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
            stats.filtered_count += 1
        elif result.state == PortState.ERROR:
            stats.error_count += 1
        
        return result

    # ====================== ENHANCED UDP SCANNING ======================

    def _advanced_udp_scan_with_filters(self, 
                                      hostname: str, 
                                      ip: str, 
                                      ports: List[int],
                                      filters: FilterConfig) -> Tuple[List[PortScanResult], ScanStatistics]:
        results: List[PortScanResult] = []
        stats = ScanStatistics()
        stats.total_scanned = len(ports)
        
        self.logger.info(f"[bhp] Advanced UDP scan with filtering on {len(ports)} ports")
        
        workers = min(self.max_workers // 2, max(5, len(ports) // 20))
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {}
            
            for port in ports:
                if not (filters.min_port <= port <= filters.max_port):
                    continue
                
                future = executor.submit(self._smart_udp_probe_with_stats, hostname, ip, port, stats)
                future_to_port[future] = port
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    error_result = PortScanResult(
                        plugin=self.name,
                        port=port,
                        protocol="udp",
                        state=PortState.ERROR,
                        reason=str(e)
                    )
                    results.append(error_result)
                    stats.error_count += 1
        
        self._update_display_stats(results, stats, filters)
        
        return results, stats

    def _smart_udp_probe_with_stats(self, 
                                  hostname: str, 
                                  ip: str, 
                                  port: int,
                                  stats: ScanStatistics) -> PortScanResult:
        """مسبار UDP مع تحديث الإحصائيات"""
        result = self._smart_udp_probe(hostname, ip, port)
        
        if result.state == PortState.OPEN:
            stats.open_count += 1
        elif result.state == PortState.CLOSED:
            stats.closed_count += 1
        elif result.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
            stats.filtered_count += 1
        elif result.state == PortState.ERROR:
            stats.error_count += 1
        
        return result

    # ====================== STATISTICS & REPORTING ======================

    def _update_display_stats(self, 
                            results: List[PortScanResult], 
                            stats: ScanStatistics,
                            filters: FilterConfig):
        """تحديث إحصائيات العرض بناءً على التصفية"""
        hidden_closed = 0
        hidden_filtered = 0
        hidden_error = 0
        
        for result in results:
            if not result.is_displayable(
                show_closed=filters.show_closed,
                show_filtered=filters.show_filtered,
                show_errors=filters.show_errors,
                min_port=filters.min_port,
                max_port=filters.max_port
            ):
                if result.state == PortState.CLOSED:
                    hidden_closed += 1
                elif result.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
                    hidden_filtered += 1
                elif result.state == PortState.ERROR:
                    hidden_error += 1
        
        stats.hidden_count = hidden_closed + hidden_filtered + hidden_error
        stats.hidden_details = {
            "closed": hidden_closed,
            "filtered": hidden_filtered,
            "error": hidden_error
        }
        stats.display_count = len(results) - stats.hidden_count

    def _merge_statistics(self, stats1: ScanStatistics, stats2: ScanStatistics) -> ScanStatistics:
        """دمج إحصائيات متعددة"""
        return ScanStatistics(
            total_scanned=stats1.total_scanned + stats2.total_scanned,
            open_count=stats1.open_count + stats2.open_count,
            closed_count=stats1.closed_count + stats2.closed_count,
            filtered_count=stats1.filtered_count + stats2.filtered_count,
            error_count=stats1.error_count + stats2.error_count,
            hidden_count=stats1.hidden_count + stats2.hidden_count,
            hidden_details={
                "closed": stats1.hidden_details.get("closed", 0) + stats2.hidden_details.get("closed", 0),
                "filtered": stats1.hidden_details.get("filtered", 0) + stats2.hidden_details.get("filtered", 0),
                "error": stats1.hidden_details.get("error", 0) + stats2.hidden_details.get("error", 0),
            },
            display_count=stats1.display_count + stats2.display_count
        )

    def _create_filter_summary(self, stats: ScanStatistics, filters: FilterConfig) -> Dict[str, Any]:
        return {
            "plugin": self.name,
            "type": "filter_summary",
            "filters_applied": {
                "show_closed": filters.show_closed,
                "show_filtered": filters.show_filtered,
                "show_errors": filters.show_errors,
                "min_port": filters.min_port,
                "max_port": filters.max_port,
                "display_filter": filters.display_filter.value
            },
            "statistics": {
                "total_scanned": stats.total_scanned,
                "displayed": stats.display_count,
                "hidden": stats.hidden_count,
                "hidden_breakdown": stats.hidden_details,
                "open": stats.open_count,
                "closed": stats.closed_count,
                "filtered": stats.filtered_count,
                "errors": stats.error_count,
                "scan_duration": round(stats.scan_duration, 2)
            },
            "notes": f"Showing {stats.display_count} of {stats.total_scanned} ports "
                    f"({stats.hidden_count} hidden by filters)"
        }

    def _generate_enhanced_intelligence_report(self, 
                                             target: str, 
                                             ip: str, 
                                             results: List[Any],
                                             stats: ScanStatistics,
                                             filters: FilterConfig) -> Dict[str, Any]:
        """توليد تقرير استخباراتي مع مراعاة التصفية"""
        displayed_results = []
        for item in results:
            if isinstance(item, dict) and item.get("state"):
                displayed_results.append(item)
        
        report = {
            "target": target,
            "ip": ip,
            "scan_time": datetime.now().isoformat(),
            "filters_applied": {
                "show_closed": filters.show_closed,
                "show_filtered": filters.show_filtered,
                "show_errors": filters.show_errors
            },
            "summary": {
                "total_ports_scanned": stats.total_scanned,
                "ports_displayed": stats.display_count,
                "ports_hidden": stats.hidden_count,
                "hidden_breakdown": stats.hidden_details,
                "open_ports": stats.open_count,
                "closed_ports": stats.closed_count,
                "filtered_ports": stats.filtered_count,
                "vulnerabilities_found": 0,
                "security_score": 0,
            },
            "displayed_open_services": [],
            "security_issues": [],
            "recommendations": [],
            "notes": []
        }
        
        for item in displayed_results:
            if isinstance(item, dict) and "state" in item:
                if item["state"] == PortState.OPEN:
                    service_info = {
                        "port": item.get("port"),
                        "protocol": item.get("protocol", "tcp"),
                        "service": item.get("service", "unknown"),
                        "banner": item.get("banner", "")[:100] if item.get("banner") else ""
                    }
                    report["displayed_open_services"].append(service_info)
            
            if isinstance(item, dict) and "vulnerabilities" in item and item["vulnerabilities"]:
                report["summary"]["vulnerabilities_found"] += len(item["vulnerabilities"])
                report["security_issues"].extend(item["vulnerabilities"])
            
            if isinstance(item, dict) and "security_score" in item:
                report["summary"]["security_score"] = max(
                    report["summary"]["security_score"],
                    item["security_score"]
                )
        
        if stats.hidden_count > 0:
            report["notes"].append(
                f"Note: {stats.hidden_count} ports hidden by filters "
                f"({stats.hidden_details.get('closed', 0)} closed, "
                f"{stats.hidden_details.get('filtered', 0)} filtered)"
            )
        
        if stats.open_count > 10:
            report["recommendations"].append("Reduce number of open ports")
        
        if report["summary"]["security_score"] < 50:
            report["recommendations"].append("Improve security headers configuration")
        
        if any("CVE-" in str(issue) for issue in report["security_issues"]):
            report["recommendations"].append("Apply security patches for discovered vulnerabilities")
        
        if not filters.show_closed and stats.closed_count > 100:
            report["notes"].append(
                f"Note: {stats.closed_count} closed ports hidden "
                f"(use --show-closed to view them)"
            )
        
        return {"plugin": self.name, "enhanced_intelligence_report": report}

    # ====================== QUICK SCAN WITH FILTERS ======================

    def _quick_port_scan_with_filters(self, 
                                    hostname: str, 
                                    ip: str, 
                                    ports: List[int],
                                    filters: FilterConfig) -> Tuple[List[PortScanResult], ScanStatistics]:
        quick_results = []
        stats = ScanStatistics()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    quick_results.append(
                        PortScanResult(
                            plugin=self.name,
                            port=port,
                            protocol="tcp",
                            state=PortState.OPEN,
                            reason="quick_scan"
                        )
                    )
                    stats.open_count += 1
                else:
                    quick_results.append(
                        PortScanResult(
                            plugin=self.name,
                            port=port,
                            protocol="tcp",
                            state=PortState.CLOSED,
                            reason="quick_scan"
                        )
                    )
                    stats.closed_count += 1
                
                sock.close()
            except:
                quick_results.append(
                    PortScanResult(
                        plugin=self.name,
                        port=port,
                        protocol="tcp",
                        state=PortState.ERROR,
                        reason="quick_scan_error"
                    )
                )
                stats.error_count += 1
        
        stats.total_scanned = len(ports)
        self._update_display_stats(quick_results, stats, filters)
        
        return quick_results, stats

    # ====================== HELPER METHODS (من الأصل) ======================

    def _parse_ports_input(self, ports_input: Union[str, List[int]]) -> List[int]:
        """تحويل مدخلات المنافذ إلى قائمة"""
        if isinstance(ports_input, list):
            return ports_input
        
        ports = set()
        
        for part in str(ports_input).split(','):
            part = part.strip()
            if not part:
                continue
            
            if '-' in part:
                try:
                    start, end = part.split('-')
                    start_port, end_port = int(start.strip()), int(end.strip())
                    ports.update(range(start_port, end_port + 1))
                except ValueError:
                    self.logger.warning(f"[bhp] Invalid port range: {part}")
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    self.logger.warning(f"[bhp] Invalid port: {part}")
        
        return sorted(ports)

    def _get_default_tcp_ports(self) -> List[int]:
        common_ports = [
            *range(1, 1025),
            1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6000,
            6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9042,
            9200, 9300, 11211, 27017, 28017, 50000, 50070, 50075
        ]
        return sorted(set(common_ports))

    def _get_default_udp_ports(self) -> List[int]:
        common_udp = [53, 67, 68, 69, 123, 135, 137, 138, 139, 
                     161, 162, 445, 500, 514, 520, 1900, 4500, 
                     5353, 4789]
        return common_udp

    def _get_service_info(self, port: int, protocol: str) -> Optional[Tuple[str, str]]:
        if port in self.SERVICE_DB:
            service_name, service_type = self.SERVICE_DB[port]
            if protocol == "udp" and port in [53, 67, 68, 69, 123, 161, 162]:
                return (service_name, service_type)
            elif protocol == "tcp" and port not in [53, 67, 68, 69, 123, 161, 162]:
                return (service_name, service_type)
        return None

    def _analyze_service(self, port: int, banner: str) -> Dict[str, Any]:
        result = {
            "name": "unknown",
            "version": "unknown",
            "detected_by": "port",
            "confidence": "low"
        }
        
        service_info = self._get_service_info(port, "tcp")
        if service_info:
            result["name"] = service_info[0]
            result["detected_by"] = "port_db"
            result["confidence"] = "high"
        
        banner_lower = banner.lower()
        
        patterns = {
            "Apache": [r"apache/(\d+\.\d+(?:\.\d+)?)", r"httpd/(\d+\.\d+(?:\.\d+)?)"],
            "nginx": [r"nginx/(\d+\.\d+(?:\.\d+)?)"],
            "IIS": [r"microsoft-iis/(\d+\.\d+)", r"iis/(\d+\.\d+)"],
            "OpenSSH": [r"openssh_(\d+\.\d+(?:p\d+)?)", r"ssh-2.0-openssh_(\d+\.\d+)"],
            "MySQL": [r"mysql[ -]?(\d+\.\d+\.\d+)", r"mariadb[ -]?(\d+\.\d+\.\d+)"],
            "PostgreSQL": [r"postgresql[ -]?(\d+\.\d+(?:\.\d+)?)"],
            "Redis": [r"redis[ -]?(\d+\.\d+(?:\.\d+)?)"],
            "Dovecot": [r"dovecot[ -]?(\d+\.\d+(?:\.\d+)?)"],
        }
        
        for service_name, service_patterns in patterns.items():
            for pattern in service_patterns:
                match = re.search(pattern, banner_lower)
                if match:
                    result["name"] = service_name
                    result["version"] = match.group(1)
                    result["detected_by"] = "banner"
                    result["confidence"] = "high"
                    break
        
        return result

    def _check_advanced_vulnerabilities(self, service: str, version: str) -> List[str]:
        vulns = []
        
        vulnerability_db = {
            "Apache": {
                "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
                "2.4.50": ["CVE-2021-42013"],
                "2.4.51": ["CVE-2021-44790"],
            },
            "OpenSSH": {
                "7.2": ["CVE-2016-6515"],
                "7.4": ["CVE-2018-15473"],
                "8.0": ["CVE-2020-14145"],
                "8.4": ["CVE-2020-15778"],
            },
            "nginx": {
                "1.18.0": ["CVE-2021-23017"],
                "1.20.0": ["CVE-2021-23017"],
                "1.21.0": ["CVE-2021-23017"],
            },
            "Dovecot": {
                "2.3.16": ["CVE-2022-30550"],
                "2.3.19": ["CVE-2022-30552"],
            },
        }
        
        if service in vulnerability_db and version:
            for affected_version, cve_list in vulnerability_db[service].items():
                if affected_version in version:
                    vulns.extend(cve_list)
        
        return vulns

    def _get_advanced_certificate_info(self, hostname: str, ip: str, port: int) -> Dict[str, Any]:
        try:
        
            try:
                from cryptography import x509  
                from cryptography.hazmat.backends import default_backend 
            except ModuleNotFoundError:
                return {
                    "error": "Missing dependency: cryptography (install with: poetry add cryptography)",
                    "simple_error": True,
                }

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)

                    if not cert_bin:
                        return {"error": "No certificate found", "simple_error": True}

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                    subject = {}
                    for attr in cert.subject:
                        oid_name = getattr(attr.oid, "_name", None) or getattr(attr.oid, "dotted_string", "unknown")
                        subject[oid_name] = attr.value

                    issuer = {}
                    for attr in cert.issuer:
                        oid_name = getattr(attr.oid, "_name", None) or getattr(attr.oid, "dotted_string", "unknown")
                        issuer[oid_name] = attr.value

                    now = datetime.now()
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after

                    is_expired = now > not_after
                    expires_soon = (not_after - now).days < 30

                    pub = cert.public_key()
                    key_bits = getattr(pub, "key_size", None)

                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "version": str(cert.version),
                        "serial_number": hex(cert.serial_number),
                        "not_valid_before": not_before.isoformat(),
                        "not_valid_after": not_after.isoformat(),
                        "signature_algorithm": getattr(cert.signature_algorithm_oid, "_name", None)
                        or getattr(cert.signature_algorithm_oid, "dotted_string", "unknown"),
                        "is_expired": is_expired,
                        "expires_soon": expires_soon,
                        "days_until_expiry": (not_after - now).days,
                        "public_key_bits": key_bits,
                    }

        except Exception as e:
            return {"error": str(e), "simple_error": True}


    def _resolve_target(self, target: str) -> Tuple[Optional[str], List[str]]:
        if not target:
            return None, []
        
        try:
            ipaddress.ip_address(target)
            return target, [target]
        except ValueError:
            pass
        
        try:
            info = socket.getaddrinfo(target, None, socket.AF_INET)
            ips = [sockaddr[0] for _, _, _, _, sockaddr in info]
            
            if ips:
                return ips[0], ips
            
            info = socket.getaddrinfo(target, None, socket.AF_INET6)
            ips = [sockaddr[0] for _, _, _, _, sockaddr in info]
            
            if ips:
                return ips[0], ips
        
        except socket.gaierror:
            pass
        
        return None, []
        

    def _cfg_get(self, key: str, default: Any) -> Any:
        if self.config is None:
            return default
        
        if hasattr(self.config, key):
            return getattr(self.config, key, default)
        
        if isinstance(self.config, dict):
            return self.config.get(key, default)
        
        return default

    def _to_dict(self, obj: Any) -> Any:
        """تحويل الكائن إلى dict"""
        if hasattr(obj, "__dict__"):
            result = obj.__dict__.copy()
            
            for key in list(result.keys()):
                if result[key] is None:
                    del result[key]
            
            return result
        
        return obj

    # ====================== LEGACY METHODS (للتوافق) ======================

    def _scan_tcp_port(self, ip: str, port: int, method: str) -> PortScanResult:
        try:
            if method == "connect":
                return self._tcp_connect_scan(ip, port)
            elif method == "syn":
                return self._tcp_syn_scan(ip, port)
            else:
                return self._tcp_connect_scan(ip, port)
        
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="tcp",
                state=PortState.ERROR,
                reason=str(e),
                scan_method=method
            )

    def _tcp_connect_scan(self, ip: str, port: int) -> PortScanResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if self.stealth_mode:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_info = self._get_service_info(port, "tcp")
                
                banner = ""
                try:
                    sock.settimeout(1)
                    if port in [80, 443, 8080, 8443]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                sock.close()
                
                return PortScanResult(
                    plugin=self.name,
                    port=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=service_info[0] if service_info else "unknown",
                    banner=banner[:500] if banner else None,
                    reason="connected",
                    scan_method="connect"
                )
            else:
                sock.close()
                return PortScanResult(
                    plugin=self.name,
                    port=port,
                    protocol="tcp",
                    state=PortState.CLOSED,
                    reason=f"connect_error_{result}",
                    scan_method="connect"
                )
        
        except socket.timeout:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="tcp",
                state=PortState.FILTERED,
                reason="timeout",
                scan_method="connect"
            )
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="tcp",
                state=PortState.ERROR,
                reason=str(e),
                scan_method="connect"
            )

    def _tcp_syn_scan(self, ip: str, port: int) -> PortScanResult:
        try:
            return self._tcp_connect_scan(ip, port)
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="tcp",
                state=PortState.ERROR,
                reason=f"SYN scan failed: {str(e)}",
                scan_method="syn"
            )

    def _smart_udp_probe(self, hostname: str, ip: str, port: int) -> PortScanResult:
        start_time = time.time()
        
        service_info = self._get_service_info(port, "udp")
        service_name = service_info[0] if service_info else "unknown"
        
        try:
            if port == 53:
                return self._probe_dns_udp(hostname, ip, port, start_time)
            elif port == 123:
                return self._probe_ntp_udp(ip, port, start_time)
            elif port == 161:
                return self._probe_snmp_udp(ip, port, start_time)
            elif port == 67 or port == 68:
                return self._probe_dhcp_udp(ip, port, start_time)
            elif port == 137:
                return self._probe_netbios_udp(ip, port, start_time)
            else:
                return self._generic_udp_scan(ip, port, start_time, service_name)
        
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="udp",
                state=PortState.ERROR,
                reason=str(e),
                latency=time.time() - start_time
            )

    def _probe_dns_udp(self, hostname: str, ip: str, port: int, start_time: float) -> PortScanResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            query = self._build_dns_query("google.com")
            sock.sendto(query, (ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                latency = time.time() - start_time
                sock.close()
                
                if len(data) > 0:
                    banner = f"DNS Response: {len(data)} bytes"
                    if len(data) > 12:
                        if data[2] & 0x80:
                            banner += " [Valid DNS Response]"
                    
                    return PortScanResult(
                        plugin=self.name,
                        port=port,
                        protocol="udp",
                        state=PortState.OPEN,
                        service="DNS",
                        banner=banner,
                        reason="dns_response",
                        latency=latency
                    )
            
            except socket.timeout:
                sock.close()
                return self._generic_udp_scan(ip, port, start_time, "DNS")
        
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="udp",
                state=PortState.ERROR,
                reason=f"DNS probe failed: {str(e)}",
                latency=time.time() - start_time
            )

    def _generic_udp_scan(self, ip: str, port: int, start_time: float, service_name: str) -> PortScanResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            probe_data = b"\x00\x01\x02\x03"
            sock.sendto(probe_data, (ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                latency = time.time() - start_time
                sock.close()
                
                banner = f"UDP Response: {len(data)} bytes" if data else "Empty response"
                
                return PortScanResult(
                    plugin=self.name,
                    port=port,
                    protocol="udp",
                    state=PortState.OPEN,
                    service=service_name,
                    banner=banner,
                    reason="udp_response",
                    latency=latency
                )
            
            except socket.timeout:
                latency = time.time() - start_time
                sock.close()
                
                return PortScanResult(
                    plugin=self.name,
                    port=port,
                    protocol="udp",
                    state=PortState.OPEN_FILTERED,
                    service=service_name,
                    reason="no_response",
                    latency=latency
                )
        
        except Exception as e:
            return PortScanResult(
                plugin=self.name,
                port=port,
                protocol="udp",
                state=PortState.ERROR,
                reason=str(e),
                latency=time.time() - start_time
            )

    def _build_dns_query(self, domain: str) -> bytes:
        """بناء استعلام DNS بسيط"""
        packet_id = random.randint(0, 65535)
        flags = 0x0100
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        
        header = struct.pack("!HHHHHH", packet_id, flags, qdcount, ancount, nscount, arcount)
        
        question = b""
        for part in domain.split('.'):
            question += struct.pack("B", len(part)) + part.encode()
        question += b"\x00"
        
        question += struct.pack("!HH", 1, 1)
        
        return header + question

    def _advanced_banner_grab(self, hostname: str, ip: str, ports: List[int]) -> List[BannerInfo]:
        results: List[BannerInfo] = []
        
        for port in ports:
            try:
                banner_data = self._smart_banner_grab(hostname, ip, port)
                raw_banner = banner_data.get("raw", "")
                
                if raw_banner and not raw_banner.startswith("Error:"):
                    service_info = self._analyze_service(port, raw_banner)
                    
                    vulnerabilities = self._check_advanced_vulnerabilities(
                        service_info["name"], service_info.get("version")
                    )
                    
                    service_details = {
                        "port": port,
                        "protocol": banner_data.get("protocol", "tcp"),
                        "detected_by": service_info.get("detected_by", "banner"),
                        "confidence": service_info.get("confidence", "medium")
                    }
                    
                    cert_info = None
                    if port in [443, 8443]:
                        cert_info = self._get_advanced_certificate_info(hostname, ip, port)
                    
                    banner_info = BannerInfo(
                        plugin=self.name,
                        service=service_info["name"],
                        raw_banner=raw_banner[:1000],
                        parsed_data=banner_data.get("parsed", {}),
                        vulnerabilities=vulnerabilities,
                        cert_info=cert_info,
                        service_details=service_details
                    )
                    
                    results.append(banner_info)
            
            except Exception as e:
                self.logger.warning(f"[bhp] Advanced banner grab failed on port {port}: {e}")
        
        return results

    def _smart_banner_grab(self, hostname: str, ip: str, port: int) -> Dict[str, Any]:
        result = {"raw": "", "parsed": {}, "protocol": "tcp"}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            if port in [80, 8080, 8000, 8008]:
                request = f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: {self.user_agent}\r\n\r\n"
                sock.send(request.encode())
            
            elif port in [443, 8443]:
                request = f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: {self.user_agent}\r\n\r\n"
                sock.send(request.encode())
            
            elif port == 21:
                sock.send(b"\r\n")
            
            elif port == 22:
                sock.send(b"SSH-2.0-Client\r\n")
            
            elif port == 25:
                sock.send(f"EHLO {hostname}\r\n".encode())
            
            elif port == 110:
                sock.send(b"CAPA\r\n")
            
            elif port == 143:
                sock.send(b"A001 CAPABILITY\r\n")
            
            elif port == 3306:
                sock.send(b"\x00")
            
            else:
                sock.send(b"\r\n")
                time.sleep(0.5)
                sock.send(b"HELP\r\n")
            
            try:
                banner = b""
                sock.settimeout(2)
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) >= 4096:
                        break
                
                raw_banner = banner.decode('utf-8', errors='ignore').strip()
                result["raw"] = raw_banner
                
                if port in [80, 443, 8080, 8443] and "HTTP" in raw_banner:
                    self._parse_http_response(raw_banner, result)
            
            except socket.timeout:
                result["raw"] = "Timeout waiting for response"
            
            sock.close()
        
        except Exception as e:
            result["raw"] = f"Error: {str(e)}"
        
        return result

    def _parse_http_response(self, raw_response: str, result: Dict[str, Any]):
        lines = raw_response.split('\n')
        if lines:
            result["parsed"]["status"] = lines[0].strip()
            result["parsed"]["headers"] = {}
            
            for line in lines[1:]:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    result["parsed"]["headers"][key.strip()] = value.strip()

    def _advanced_header_analysis(self, hostname: str, ip: str) -> List[HeaderAnalysis]:
        results: List[HeaderAnalysis] = []
        
        urls_to_check = [
            f"http://{hostname}",
            f"https://{hostname}",
            f"http://{ip}",
            f"https://{ip}",
            f"http://{hostname}:8080",
            f"https://{hostname}:8443",
        ]
        
        for url in urls_to_check:
            try:
                clean_url = url.replace(":80", "").replace(":443", "")
                
                session = requests.Session()
                session.max_redirects = 5
                session.verify = False
                
                redirect_chain = []
                
                try:
                    response = session.get(
                        clean_url,
                        timeout=self.timeout,
                        headers={"User-Agent": self.user_agent},
                        allow_redirects=True
                    )
                    
                    if response.history:
                        for resp in response.history:
                            redirect_chain.append({
                                "url": resp.url,
                                "status": resp.status_code,
                                "location": resp.headers.get("Location", "")
                            })
                    
                    headers_dict = dict(response.headers)
                    security_score, missing, vulns = self._analyze_security_headers(headers_dict)
                    server_info = self._extract_server_info(headers_dict)
                    cookie_analysis = self._analyze_cookies(response)
                    
                    security_analysis = self._analyze_security_configuration(headers_dict, response.url)
                    
                    all_vulnerabilities = vulns + security_analysis.get("issues", [])
                    
                    result = HeaderAnalysis(
                        plugin=self.name,
                        url=clean_url,
                        headers=headers_dict,
                        security_score=security_score,
                        missing_security_headers=missing,
                        vulnerabilities=all_vulnerabilities,
                        server_info=server_info,
                        cookie_analysis=cookie_analysis,
                        redirect_chain=redirect_chain
                    )
                    
                    results.append(result)
                    
                    self.logger.info(f"[bhp] Analyzed {clean_url} - Security: {security_score}/100")
                
                except requests.exceptions.TooManyRedirects:
                    self.logger.warning(f"[bhp] Too many redirects for {clean_url}")
                
            except requests.RequestException:
                continue
            except Exception as e:
                self.logger.warning(f"[bhp] Header analysis error for {url}: {e}")
        
        return results

    def _analyze_security_configuration(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        analysis = {"issues": [], "recommendations": []}
        
        hsts = headers.get("Strict-Transport-Security", "")
        if "max-age" in hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    analysis["issues"].append(f"HSTS max-age too low: {max_age}")
        
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                analysis["issues"].append("CSP contains unsafe directives")
        else:
            analysis["issues"].append("Missing Content-Security-Policy")
        
        if "Access-Control-Allow-Origin" in headers:
            if headers["Access-Control-Allow-Origin"] == "*":
                analysis["issues"].append("CORS wildcard (*) enabled")
        
        if url.startswith("https://") and "Strict-Transport-Security" not in headers:
            analysis["recommendations"].append("Add HSTS header")
        
        if not headers.get("X-Content-Type-Options"):
            analysis["recommendations"].append("Add X-Content-Type-Options: nosniff")
        
        return analysis

    def _analyze_security_headers(self, headers: Dict[str, str]) -> Tuple[int, List[str], List[str]]:
        score = 100
        missing: List[str] = []
        vulnerabilities: List[str] = []
        
        for header in self.security_headers:
            if header not in headers:
                missing.append(header)
                score -= 8
        
        if "X-Frame-Options" in headers:
            v = headers["X-Frame-Options"]
            if v.upper() not in ("DENY", "SAMEORIGIN"):
                vulnerabilities.append(f"Weak X-Frame-Options: {v}")
                score -= 5
        
        if headers.get("X-XSS-Protection") == "0":
            vulnerabilities.append("X-XSS-Protection disabled")
            score -= 10
        
        if "Server" in headers and re.search(r"\d+\.\d+", headers["Server"]):
            vulnerabilities.append("Server version disclosure")
            score -= 5
        
        if headers.get("Access-Control-Allow-Origin") == "*":
            vulnerabilities.append("CORS wildcard enabled")
            score -= 8
        
        return max(0, score), missing, vulnerabilities

    def _extract_server_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        
        server = headers.get("Server")
        if server:
            info["server"] = server
            s = server.lower()
            
            if "apache" in s:
                info["technology"] = "Apache"
                m = re.search(r"apache/(\d+\.\d+(?:\.\d+)?)", s)
                if m:
                    info["version"] = m.group(1)
            elif "nginx" in s:
                info["technology"] = "nginx"
                m = re.search(r"nginx/(\d+\.\d+(?:\.\d+)?)", s)
                if m:
                    info["version"] = m.group(1)
            elif "iis" in s:
                info["technology"] = "IIS"
        
        if "X-Powered-By" in headers:
            info["powered_by"] = headers["X-Powered-By"]
        
        return info

    def _analyze_cookies(self, response: requests.Response) -> Dict[str, Any]:
        analysis = {"count": 0, "cookies": [], "security_issues": []}
        
        try:
            cookies = response.cookies
            analysis["count"] = len(cookies)
            
            for c in cookies:
                info = {
                    "name": c.name,
                    "secure": bool(getattr(c, "secure", False)),
                    "path": getattr(c, "path", "/"),
                }
                analysis["cookies"].append(info)
                
                if not info["secure"]:
                    analysis["security_issues"].append(f"Cookie '{c.name}' not secure")
        
        except Exception:
            pass
        
        return analysis

    # ====================== LEGACY WRAPPER METHODS ======================

    def _port_scan(self, ip: str, ports: List[int], protocol: str = "tcp") -> List[PortScanResult]:
        results, _ = self._advanced_port_scan_with_filters(
            "unknown", ip, ports, protocol, "connect", 
            FilterConfig(show_closed=True, show_filtered=True, show_errors=True)
        )
        return results

    def _banner_grab(self, hostname: str, ip: str, ports: List[int]) -> List[BannerInfo]:
        return self._advanced_banner_grab(hostname, ip, ports)

    def _analyze_headers(self, target: str) -> List[HeaderAnalysis]:
        ip, _ = self._resolve_target(target)
        if ip:
            return self._advanced_header_analysis(target, ip)
        return []

    def _scan_udp_port(self, ip: str, port: int) -> PortScanResult:
        return self._smart_udp_probe("unknown", ip, port)

    def _get_ssl_certificate(self, hostname: str, ip: str, port: int) -> Dict[str, Any]:
        return self._get_advanced_certificate_info(hostname, ip, port)


__all__ = ["bhp", "PortScanResult", "BannerInfo", "HeaderAnalysis"]
