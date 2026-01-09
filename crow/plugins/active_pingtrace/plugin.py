"""
active_pingtrace/plugin.py - Advanced Ping & Traceroute Plugin
أداة متقدمة لاختبار الاتصال وتتبع المسار مع تحليل شبكي متكامل
"""

import sys
import time
import socket
import struct
import select
import ipaddress
import statistics
import subprocess
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

from crow.core.bases import ActivePlugin
from crow.core.models import PluginOutput


# ====================== ENUMS ======================

class ProtocolType(str, Enum):
    """أنواع البروتوكولات المدعومة"""
    ICMP = "icmp"
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"


class PacketStatus(str, Enum):
    """حالات الحزمة"""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    FILTERED = "filtered"
    ERROR = "error"


class ScanMode(str, Enum):
    """أنواع المسح"""
    PING = "ping"
    TRACEROUTE = "traceroute"
    BOTH = "both"


# ====================== DATA MODELS ======================

@dataclass
class PingResult:
    """نتيجة اختبار Ping"""
    sequence: int
    target: str
    ip: str
    status: PacketStatus
    rtt: float  # Round Trip Time in ms
    ttl: Optional[int] = None
    packet_size: int = 64
    protocol: ProtocolType = ProtocolType.ICMP
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source_ip: Optional[str] = None
    dest_port: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HopResult:
    """نتيجة قفزة في Traceroute"""
    hop_number: int
    ip_address: Optional[str]
    hostname: Optional[str]
    status: PacketStatus
    rtts: List[float]
    avg_rtt: float
    min_rtt: float
    max_rtt: float
    packet_loss: float
    ttl: int
    protocol: ProtocolType = ProtocolType.ICMP
    as_number: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSummary:
    """ملخص المسح"""
    target: str
    ip: str
    mode: str
    protocol: str
    start_time: str
    end_time: str
    duration: float
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss: float = 0.0
    avg_rtt: float = 0.0
    min_rtt: float = 0.0
    max_rtt: float = 0.0
    total_hops: int = 0
    successful_hops: int = 0
    failed_hops: int = 0
    issues_detected: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ====================== ICMP ENGINE ======================

class ICMPSocket:
    """مدير ICMP Socket مع دعم متعدد الأنظمة"""
    
    def __init__(self, timeout=2.0, ttl=64):
        self.timeout = timeout
        self.ttl = ttl
        self.is_windows = sys.platform.startswith('win')
        self.is_linux = sys.platform.startswith('linux')
        self.is_darwin = sys.platform.startswith('darwin')
        self.socket = None
        self.sequence = 0
        self.packet_id = 12345
        
    def __enter__(self):
        self.create_socket()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def create_socket(self):
        """إنشاء ICMP socket حسب النظام"""
        try:
            if self.is_windows:
                # Windows requires SOCK_RAW with protocol=1 (ICMP)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            else:
                # Linux/Mac allow SOCK_DGRAM for ICMP (لا تحتاج root)
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            
            self.socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            self.socket.settimeout(self.timeout)
            return True
        except PermissionError:
            # إذا لم تكن هناك صلاحيات root، استخدم ping command
            return False
        except Exception as e:
            return False
    
    def calculate_checksum(self, data: bytes) -> int:
        """حساب checksum لـ ICMP"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff
    
    def build_icmp_packet(self, sequence: int, data_size: int = 64) -> bytes:
        """بناء حزمة ICMP Echo Request"""
        self.sequence = sequence
        
        # ICMP Header (Type=8, Code=0)
        header = struct.pack('!BBHHH', 8, 0, 0, self.packet_id, sequence)
        
        # Payload
        payload = b'CROW-PING' * (data_size // 9)
        payload = payload[:data_size]
        
        # Calculate checksum
        checksum = self.calculate_checksum(header + payload)
        header = struct.pack('!BBHHH', 8, 0, checksum, self.packet_id, sequence)
        
        return header + payload
    
    def send_ping(self, target_ip: str, sequence: int, data_size: int = 64) -> Tuple[bool, float, Optional[int]]:
        """إرسال ping وحساب RTT"""
        try:
            packet = self.build_icmp_packet(sequence, data_size)
            start_time = time.time()
            
            self.socket.sendto(packet, (target_ip, 0))
            
            # استقبال الرد
            ready = select.select([self.socket], [], [], self.timeout)
            if ready[0]:
                response, addr = self.socket.recvfrom(1024)
                rtt = (time.time() - start_time) * 1000  # تحويل لـ milliseconds
                
                # استخراج TTL من IP header
                ttl = response[8] if len(response) > 8 else None
                
                return True, rtt, ttl
            else:
                return False, self.timeout * 1000, None
                
        except socket.timeout:
            return False, self.timeout * 1000, None
        except Exception as e:
            return False, 0, None
    
    def close(self):
        """إغلاق السوكيت"""
        if self.socket:
            self.socket.close()


# ====================== SYSTEM PING FALLBACK ======================

class SystemPing:
    """استخدام system ping command كبديل"""
    
    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
    
    def ping(self, target: str, count: int = 4, timeout: int = 2) -> List[Dict]:
        """تنفيذ ping باستخدام الأمر النظامي"""
        try:
            if self.is_windows:
                cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), target]
            else:
                cmd = ['ping', '-c', str(count), '-W', str(timeout), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 5)
            
            return self.parse_ping_output(result.stdout, target)
            
        except subprocess.TimeoutExpired:
            return [{"status": "timeout", "target": target, "error": "Command timeout"}]
        except Exception as e:
            return [{"status": "error", "target": target, "error": str(e)}]
    
    def parse_ping_output(self, output: str, target: str) -> List[Dict]:
        """تحليل مخرجات أمر ping"""
        results = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # البحث عن سطور الرد
            if 'time=' in line.lower() or 'ttl=' in line.lower():
                try:
                    # استخراج RTT
                    if 'time=' in line:
                        time_part = line.split('time=')[1].split()[0]
                        rtt = float(time_part.replace('ms', '').replace('ms<', ''))
                    else:
                        rtt = 0
                    
                    # استخراج TTL
                    if 'ttl=' in line:
                        ttl_part = line.split('ttl=')[1].split()[0]
                        ttl = int(ttl_part)
                    else:
                        ttl = None
                    
                    results.append({
                        "status": "success",
                        "target": target,
                        "rtt": rtt,
                        "ttl": ttl,
                        "raw_line": line
                    })
                    
                except:
                    continue
        
        return results


# ====================== TRACEROUTE ENGINE ======================

class TracerouteEngine:
    """محرك Traceroute متعدد البروتوكولات"""
    
    def __init__(self, timeout=1.0, max_hops=30):
        self.timeout = timeout
        self.max_hops = max_hops
        self.port = 33434  # المنفذ الافتراضي لـ traceroute
        self.is_windows = sys.platform.startswith('win')
    
    def icmp_traceroute(self, target_ip: str) -> List[Dict]:
        """تنفيذ traceroute باستخدام ICMP"""
        hops = []
        
        for ttl in range(1, self.max_hops + 1):
            try:
                # إنشاء raw socket للـ ICMP
                if self.is_windows:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
                
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sock.settimeout(self.timeout)
                
                # بناء حزمة ICMP
                packet_id = 12345
                checksum = 0
                header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, ttl)
                data = b'CROW-TRACE' * 6
                checksum = self._calculate_checksum(header + data)
                header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, ttl)
                packet = header + data
                
                start_time = time.time()
                sock.sendto(packet, (target_ip, 0))
                
                try:
                    response, addr = sock.recvfrom(1024)
                    rtt = (time.time() - start_time) * 1000
                    
                    # تحليل الرد
                    hop_ip = addr[0]
                    hop_hostname = self._reverse_dns(hop_ip) if hop_ip else None
                    
                    hops.append({
                        "hop": ttl,
                        "ip": hop_ip,
                        "hostname": hop_hostname,
                        "rtt": rtt,
                        "status": "success"
                    })
                    
                    # إذا وصلنا للهدف، توقف
                    if hop_ip == target_ip:
                        break
                        
                except socket.timeout:
                    hops.append({
                        "hop": ttl,
                        "ip": None,
                        "hostname": None,
                        "rtt": self.timeout * 1000,
                        "status": "timeout"
                    })
                
                sock.close()
                
            except Exception as e:
                hops.append({
                    "hop": ttl,
                    "ip": None,
                    "hostname": None,
                    "rtt": 0,
                    "status": "error",
                    "error": str(e)
                })
        
        return hops
    
    def udp_traceroute(self, target_ip: str) -> List[Dict]:
        """تنفيذ traceroute باستخدام UDP"""
        hops = []
        
        for ttl in range(1, self.max_hops + 1):
            try:
                # إنشاء UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sock.settimeout(self.timeout)
                
                # إرسال بيانات UDP
                data = b'CROW-UDP-TRACE'
                start_time = time.time()
                
                try:
                    # إرسال إلى منفذ غير مستخدم (قد يسبب ICMP Port Unreachable)
                    sock.sendto(data, (target_ip, self.port))
                    
                    try:
                        # محاولة استقبال الرد (ICMP Time Exceeded)
                        response, addr = sock.recvfrom(1024)
                        rtt = (time.time() - start_time) * 1000
                        hop_ip = addr[0]
                        
                        hops.append({
                            "hop": ttl,
                            "ip": hop_ip,
                            "rtt": rtt,
                            "status": "success"
                        })
                        
                        if hop_ip == target_ip:
                            break
                            
                    except socket.timeout:
                        # لم نحصل على رد ICMP
                        hops.append({
                            "hop": ttl,
                            "ip": None,
                            "rtt": self.timeout * 1000,
                            "status": "filtered"
                        })
                        
                except Exception as e:
                    hops.append({
                        "hop": ttl,
                        "ip": None,
                        "rtt": 0,
                        "status": "error",
                        "error": str(e)
                    })
                
                sock.close()
                
            except Exception as e:
                hops.append({
                    "hop": ttl,
                    "ip": None,
                    "rtt": 0,
                    "status": "error",
                    "error": str(e)
                })
        
        return hops
    
    def system_traceroute(self, target: str) -> List[Dict]:
        """استخدام system traceroute command"""
        try:
            if self.is_windows:
                cmd = ['tracert', '-h', str(self.max_hops), '-w', str(int(self.timeout * 1000)), target]
            else:
                cmd = ['traceroute', '-m', str(self.max_hops), '-w', str(self.timeout), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return self.parse_traceroute_output(result.stdout, target)
            
        except subprocess.TimeoutExpired:
            return [{"status": "timeout", "target": target, "error": "Command timeout"}]
        except FileNotFoundError:
            return [{"status": "error", "target": target, "error": "traceroute command not found"}]
        except Exception as e:
            return [{"status": "error", "target": target, "error": str(e)}]
    
    def parse_traceroute_output(self, output: str, target: str) -> List[Dict]:
        """تحليل مخرجات traceroute"""
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # تخطي الأسطر الفارغة والرأسية
            if not line or 'traceroute' in line.lower() or 'tracing route' in line.lower():
                continue
            
            try:
                # البحث عن نمط القفزة (مثل: "1  192.168.1.1  1.234 ms")
                parts = line.split()
                if len(parts) >= 2:
                    hop_num = int(parts[0])
                    
                    # البحث عن IP
                    ip = None
                    for part in parts[1:]:
                        if self._is_ip_address(part):
                            ip = part
                            break
                    
                    # البحث عن RTT
                    rtt = None
                    for part in parts:
                        if 'ms' in part:
                            try:
                                rtt = float(part.replace('ms', '').replace('<', ''))
                                break
                            except:
                                pass
                    
                    hops.append({
                        "hop": hop_num,
                        "ip": ip,
                        "rtt": rtt or 0,
                        "status": "success" if ip else "timeout"
                    })
                    
            except Exception as e:
                continue
        
        return hops
    
    def _calculate_checksum(self, data: bytes) -> int:
        """حساب checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1]
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff
    
    def _reverse_dns(self, ip: str) -> Optional[str]:
        """DNS عكسي"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def _is_ip_address(self, text: str) -> bool:
        """التحقق إذا كان النص عنوان IP"""
        try:
            ipaddress.ip_address(text)
            return True
        except:
            return False


# ====================== MAIN PLUGIN CLASS ======================

class pingtrace(ActivePlugin):
    """
    Advanced Active Ping & Traceroute Plugin
    أداة متقدمة لاختبار الاتصال وتتبع المسار مع تحليل شبكي متكامل
    """
    
    name = "pingtrace"
    description = "Advanced Active Ping & Traceroute with Network Analysis"
    version = "1.0.0"
    
    def __init__(self, config=None, logger=None):
        super().__init__(config, logger)
        self.logger = logger or self._create_default_logger()
        self.system_ping = SystemPing()
        self.traceroute = TracerouteEngine()
        
        # إحصائيات
        self.packets_sent = 0
        self.packets_received = 0
        
    def _create_default_logger(self):
        """إنشاء logger افتراضي"""
        import logging
        logger = logging.getLogger("pingtrace")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(name)s] %(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
    
    def _resolve_target(self, target: str) -> Optional[str]:
        """تحليل الهدف إلى IP"""
        try:
            # تنظيف الهدف
            clean_target = target.strip()
            if clean_target.startswith(('http://', 'https://')):
                clean_target = clean_target.split('://')[1]
            
            clean_target = clean_target.split('/')[0].split(':')[0]
            
            # إذا كان IP بالفعل
            try:
                ipaddress.ip_address(clean_target)
                return clean_target
            except ValueError:
                pass
            
            # تحليل DNS
            return socket.gethostbyname(clean_target)
            
        except socket.gaierror:
            self.logger.error(f"Failed to resolve target: {target}")
            return None
        except Exception as e:
            self.logger.error(f"DNS resolution error: {e}")
            return None
    
    def _parse_kwargs(self, kwargs: Dict) -> Dict:
        """تحليل المعلمات"""
        defaults = {
            'mode': 'ping',
            'protocol': 'icmp',
            'count': 4,
            'timeout': 2.0,
            'max_hops': 30,
            'packet_size': 64,
            'fast': False,
            'resolve_dns': True
        }
        
        parsed = defaults.copy()
        
        # تحويل kwargs
        for key, value in kwargs.items():
            if key in parsed:
                # تحويل الأنواع
                if key in ['count', 'max_hops', 'packet_size']:
                    try:
                        parsed[key] = int(value)
                    except:
                        pass
                elif key in ['timeout']:
                    try:
                        parsed[key] = float(value)
                    except:
                        pass
                elif key in ['fast', 'resolve_dns']:
                    parsed[key] = str(value).lower() in ['true', 'yes', '1', 'on']
                else:
                    parsed[key] = value
        
        return parsed
    
    def _perform_ping(self, target_ip: str, config: Dict) -> List[Dict]:
        """تنفيذ ping"""
        self.logger.info(f"Performing ping to {target_ip} with protocol: {config['protocol']}")
        
        results = []
        
        if config['protocol'] == 'icmp':
            # محاولة ICMP مباشرة أولاً
            try:
                with ICMPSocket(timeout=config['timeout']) as icmp_sock:
                    if icmp_sock.socket:
                        for seq in range(config['count']):
                            success, rtt, ttl = icmp_sock.send_ping(target_ip, seq, config['packet_size'])
                            
                            result = {
                                "sequence": seq + 1,
                                "target": target_ip,
                                "status": "success" if success else "timeout",
                                "rtt": rtt,
                                "ttl": ttl,
                                "protocol": "icmp",
                                "packet_size": config['packet_size']
                            }
                            results.append(result)
                            
                            self.packets_sent += 1
                            if success:
                                self.packets_received += 1
                            
                            time.sleep(0.1)  # تأخير بين الحزم
                    else:
                        # Fallback إلى system ping
                        self.logger.warning("ICMP socket failed, using system ping")
                        results = self.system_ping.ping(target_ip, config['count'], config['timeout'])
            except Exception as e:
                self.logger.error(f"ICMP ping error: {e}, using system ping")
                results = self.system_ping.ping(target_ip, config['count'], config['timeout'])
        
        elif config['protocol'] == 'tcp':
            # TCP ping (connect/close)
            for seq in range(config['count']):
                try:
                    start_time = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(config['timeout'])
                    sock.connect((target_ip, 80))  # محاولة HTTP port
                    rtt = (time.time() - start_time) * 1000
                    sock.close()
                    
                    results.append({
                        "sequence": seq + 1,
                        "target": target_ip,
                        "status": "success",
                        "rtt": rtt,
                        "protocol": "tcp",
                        "port": 80
                    })
                    
                except socket.timeout:
                    results.append({
                        "sequence": seq + 1,
                        "target": target_ip,
                        "status": "timeout",
                        "rtt": config['timeout'] * 1000,
                        "protocol": "tcp"
                    })
                except Exception as e:
                    results.append({
                        "sequence": seq + 1,
                        "target": target_ip,
                        "status": "error",
                        "error": str(e),
                        "protocol": "tcp"
                    })
                
                time.sleep(0.1)
        
        return results
    
    def _perform_traceroute(self, target_ip: str, config: Dict) -> List[Dict]:
        """تنفيذ traceroute"""
        self.logger.info(f"Performing traceroute to {target_ip} with protocol: {config['protocol']}")
        
        if config['protocol'] == 'icmp':
            # محاولة ICMP traceroute
            try:
                return self.traceroute.icmp_traceroute(target_ip)
            except Exception as e:
                self.logger.error(f"ICMP traceroute failed: {e}, using system traceroute")
                return self.traceroute.system_traceroute(target_ip)
        
        elif config['protocol'] == 'udp':
            return self.traceroute.udp_traceroute(target_ip)
        
        else:
            # استخدام system traceroute
            return self.traceroute.system_traceroute(target_ip)
    
    def _analyze_results(self, ping_results: List[Dict], trace_results: List[Dict], 
                        target: str, target_ip: str, config: Dict) -> Dict:
        """تحليل النتائج وإنشاء الملخص"""
        
        # تحليل ping
        ping_stats = {
            "sent": len(ping_results),
            "received": sum(1 for r in ping_results if r.get("status") == "success"),
            "rtt_values": [r.get("rtt", 0) for r in ping_results if r.get("rtt")],
            "packet_loss": 0.0,
            "avg_rtt": 0.0,
            "min_rtt": 0.0,
            "max_rtt": 0.0
        }
        
        if ping_stats["sent"] > 0:
            ping_stats["packet_loss"] = ((ping_stats["sent"] - ping_stats["received"]) / ping_stats["sent"]) * 100
        
        if ping_stats["rtt_values"]:
            ping_stats["avg_rtt"] = statistics.mean(ping_stats["rtt_values"])
            ping_stats["min_rtt"] = min(ping_stats["rtt_values"])
            ping_stats["max_rtt"] = max(ping_stats["rtt_values"])
        
        # تحليل traceroute
        trace_stats = {
            "total_hops": len(trace_results),
            "successful_hops": sum(1 for r in trace_results if r.get("status") == "success"),
            "failed_hops": sum(1 for r in trace_results if r.get("status") in ["timeout", "error"]),
            "hops": trace_results
        }
        
        # إنشاء الملخص
        summary = {
            "target": target,
            "ip": target_ip,
            "mode": config['mode'],
            "protocol": config['protocol'],
            "ping_stats": ping_stats,
            "traceroute_stats": trace_stats,
            "issues": [],
            "recommendations": []
        }
        
        # اكتشاف المشاكل
        if ping_stats["packet_loss"] > 20:
            summary["issues"].append(f"High packet loss: {ping_stats['packet_loss']:.1f}%")
            summary["recommendations"].append("Check network connectivity and firewall rules")
        
        if ping_stats["avg_rtt"] > 200:  # أكثر من 200ms
            summary["issues"].append(f"High latency: {ping_stats['avg_rtt']:.1f}ms")
            summary["recommendations"].append("Consider using closer server or CDN")
        
        if trace_stats["failed_hops"] > 5:
            summary["issues"].append(f"Multiple failed hops: {trace_stats['failed_hops']}")
            summary["recommendations"].append("Network path may have firewalls blocking ICMP/UDP")
        
        return summary
    
    def run(self, target: str, port: int = None, **kwargs) -> PluginOutput:
        """
        تشغيل البلوقين الرئيسي
        
        Args:
            target: الهدف (IP أو hostname)
            port: المنفذ (غير مستخدم حالياً، للحفاظ على التوافق)
            **kwargs:
                mode: ping|traceroute|both (default: ping)
                protocol: icmp|tcp|udp (default: icmp)
                count: عدد محاولات ping (default: 4)
                timeout: مهلة الانتظار بالثواني (default: 2)
                max_hops: أقصى عدد قفزات (default: 30)
                packet_size: حجم الحزمة (default: 64)
                fast: الوضع السريع (default: False)
                resolve_dns: تفعيل DNS العكسي (default: True)
        """
        start_time = time.time()
        results = []
        errors = []
        
        try:
            self.logger.info(f"Starting pingtrace scan for: {target}")
            
            # تحليل الهدف
            target_ip = self._resolve_target(target)
            if not target_ip:
                errors.append(f"Failed to resolve target: {target}")
                return PluginOutput(plugin=self.name, results=results, errors=errors)
            
            self.logger.info(f"Resolved {target} → {target_ip}")
            
            # تحليل المعلمات
            config = self._parse_kwargs(kwargs)
            
            ping_results = []
            trace_results = []
            
            # تنفيذ حسب النوع
            if config['mode'] in ['ping', 'both']:
                ping_results = self._perform_ping(target_ip, config)
                results.append({
                    "type": "ping_results",
                    "target": target,
                    "target_ip": target_ip,
                    "config": config,
                    "data": ping_results
                })
            
            if config['mode'] in ['traceroute', 'both']:
                trace_results = self._perform_traceroute(target_ip, config)
                results.append({
                    "type": "traceroute_results",
                    "target": target,
                    "target_ip": target_ip,
                    "config": config,
                    "data": trace_results
                })
            
            # تحليل النتائج
            if ping_results or trace_results:
                analysis = self._analyze_results(ping_results, trace_results, target, target_ip, config)
                results.append({
                    "type": "analysis",
                    "summary": analysis
                })
            
            scan_duration = time.time() - start_time
            
            # إضافة metadata
            results.append({
                "type": "metadata",
                "scan_duration": f"{scan_duration:.2f}s",
                "packets_sent": self.packets_sent,
                "packets_received": self.packets_received,
                "plugin_version": self.version,
                "timestamp": datetime.now().isoformat()
            })
            
            self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
        return PluginOutput(
            plugin=self.name,
            results=results,
            errors=errors
        )


# ====================== PLUGIN EXPORT ======================

# الملاحظة: PluginRegistry سيكتشف البلوقين تلقائياً إذا كان في المسار الصحيح