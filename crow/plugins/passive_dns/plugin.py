# crow/plugins/passive_dns/plugin.py
from __future__ import annotations

import ipaddress
import random
import string
from typing import Any, Dict, Iterable, List, Optional, Set

import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename

from crow.core.bases import PassivePlugin
from crow.core.logger import logger
from crow.core.models import PluginOutput

Record = Dict[str, Any]


def _rand_label(n: int = 12) -> str:
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(n)
    )


def _resolver(
    nameservers: Optional[List[str]] = None, timeout: float = 3.0
) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    if nameservers:
        r.nameservers = nameservers
    return r


def resolve_rr(
    domain: str,
    rtype: str,
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
) -> List[Record]:
    """Resolve a DNS RR type and return normalized records list."""
    res = _resolver(nameservers, timeout)
    out: List[Record] = []

    try:
        ans = res.resolve(domain, rtype)
        ttl = getattr(ans.rrset, "ttl", None)

        for r in ans:
            rec: Record = {"type": rtype, "name": domain, "ttl": ttl}

            if rtype in ("A", "AAAA"):
                rec["address"] = r.address

            elif rtype == "NS":
                rec["target"] = str(r.target).rstrip(".")

            elif rtype == "MX":
                rec["priority"] = int(r.preference)
                rec["target"] = str(r.exchange).rstrip(".")

            elif rtype == "SOA":
                rec["mname"] = str(r.mname).rstrip(".")
                rec["rname"] = str(r.rname).rstrip(".")
                rec["serial"] = int(r.serial)

            elif rtype == "TXT":
                # Join TXT chunks
                # dnspython may return list of bytes; keep it robust.
                strings = getattr(r, "strings", None)
                if strings is None:
                    # Some versions expose .strings differently; fallback:
                    rec["strings"] = str(r)
                else:
                    rec["strings"] = "".join(
                        [
                            s.decode(errors="ignore")
                            if isinstance(s, (bytes, bytearray))
                            else str(s)
                            for s in strings
                        ]
                    )

            elif rtype == "CAA":
                rec["flags"] = int(r.flags)
                rec["tag"] = str(r.tag)
                rec["value"] = str(r.value)

            elif rtype == "CNAME":
                rec["target"] = str(r.target).rstrip(".")

            elif rtype == "DNSKEY":
                rec["flags"] = int(r.flags)
                rec["protocol"] = int(r.protocol)
                rec["algorithm"] = int(r.algorithm)
                rec["key"] = str(r.key)

            else:
                rec["value"] = str(r)

            out.append(rec)

    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception:
        return []

    return out


def check_wildcard(
    domain: str, nameservers: Optional[List[str]] = None, timeout: float = 3.0
) -> Record:
    """Detect wildcard DNS by resolving random subdomain."""
    test = f"{_rand_label(16)}.{domain}"
    a = resolve_rr(test, "A", nameservers, timeout)
    aaaa = resolve_rr(test, "AAAA", nameservers, timeout)

    ips: Set[str] = set()
    for r in a:
        if "address" in r:
            ips.add(r["address"])
    for r in aaaa:
        if "address" in r:
            ips.add(r["address"])

    return {
        "type": "WILDCARD",
        "name": domain,
        "wildcard_enabled": bool(ips),
        "wildcard_ips": sorted(ips),
        "test_name": test,
    }


def check_recursive(nameserver: str, timeout: float = 3.0) -> Record:
    """Check if NS allows recursion by looking for RA flag."""
    try:
        q = dns.message.make_query("www.google.com.", dns.rdatatype.NS)
        r = dns.query.udp(q, nameserver, timeout=timeout)
        flags_txt = dns.flags.to_text(r.flags)
        recursive = "RA" in flags_txt
        return {
            "type": "RECURSION",
            "nameserver": nameserver,
            "recursive": recursive,
            "flags": flags_txt,
        }
    except Exception:
        return {
            "type": "RECURSION",
            "nameserver": nameserver,
            "recursive": False,
            "error": "failed",
        }


def check_bindversion(nameserver: str, timeout: float = 3.0) -> Record:
    """Attempt to query version.bind (TXT, CHAOS)."""
    try:
        q = dns.message.make_query(
            "version.bind.", dns.rdatatype.TXT, dns.rdataclass.CH
        )
        r = dns.query.udp(q, nameserver, timeout=timeout)
        version = None
        if r.answer:
            # Keep it raw (dnspython formats it like: "version.bind. 0 CH TXT "BIND 9.x"")
            version = r.answer[0].to_text()
        return {
            "type": "BIND_VERSION",
            "nameserver": nameserver,
            "version": version or "not detected",
        }
    except Exception:
        return {
            "type": "BIND_VERSION",
            "nameserver": nameserver,
            "version": "not detected",
        }


def check_nxdomain_hijack(nameserver: str, timeout: float = 3.0) -> Record:
    """NXDOMAIN hijack test: resolves random nonexistent .com and sees if it returns an answer."""
    fake = f"{_rand_label(20)}.com"
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [nameserver]
    res.timeout = timeout
    res.lifetime = timeout

    answers: List[str] = []
    for rt in ("A", "AAAA"):
        try:
            a = res.resolve(fake, rt, tcp=True)
            for r in a:
                if hasattr(r, "address"):
                    answers.append(r.address)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            pass
        except Exception:
            pass

    return {
        "type": "NXDOMAIN_HIJACK",
        "nameserver": nameserver,
        "test_name": fake,
        "hijack_detected": bool(answers),
        "answers": answers,
    }


def parse_spf_ips(
    domain: str,
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
    _seen: Optional[Set[str]] = None,
) -> Set[str]:
    """Extract ip4/ip6 from SPF/TXT and follow include: recursively (basic)."""
    _seen = _seen or set()
    if domain in _seen:
        return set()
    _seen.add(domain)

    ips: Set[str] = set()
    txts = resolve_rr(domain, "TXT", nameservers, timeout)
    spf_txt: List[str] = []

    for r in txts:
        s = r.get("strings", "")
        if "v=spf1" in s:
            spf_txt.append(s)

    def _tokens(s: str) -> List[str]:
        return [t.strip() for t in s.split() if t.strip()]

    for s in spf_txt:
        for tok in _tokens(s):
            if tok.startswith(("ip4:", "ip6:")):
                val = tok.split(":", 1)[1]
                try:
                    net = ipaddress.ip_network(
                        val, strict=False
                    )  # supports single IP & CIDR
                    ips.add(str(net))
                except Exception:
                    pass
            elif tok.startswith("include:"):
                inc = tok.split(":", 1)[1]
                ips |= parse_spf_ips(inc, nameservers, timeout, _seen)

    return ips


COMMON_SRV = [
    "_sip._tcp.",
    "_sip._udp.",
    "_sips._tcp.",
    "_ldap._tcp.",
    "_kerberos._tcp.",
    "_kerberos._udp.",
    "_xmpp-server._tcp.",
    "_xmpp-client._tcp.",
    "_imap._tcp.",
    "_imaps._tcp.",
    "_pop3._tcp.",
    "_pop3s._tcp.",
    "_submission._tcp.",
    "_smtp._tcp.",
    "_autodiscover._tcp.",
]


def brute_srv(
    domain: str, nameservers: Optional[List[str]] = None, timeout: float = 3.0
) -> List[Record]:
    """Enumerate common SRV records."""
    res = _resolver(nameservers, timeout)
    out: List[Record] = []

    for prefix in COMMON_SRV:
        name = f"{prefix}{domain}"
        try:
            ans = res.resolve(name, "SRV")
            ttl = getattr(ans.rrset, "ttl", None)
            for r in ans:
                out.append(
                    {
                        "type": "SRV",
                        "name": name,
                        "ttl": ttl,
                        "priority": int(r.priority),
                        "weight": int(r.weight),
                        "port": int(r.port),
                        "target": str(r.target).rstrip("."),
                    }
                )
        except Exception:
            pass

    return out


def brute_subdomains(
    domain: str,
    words: Iterable[str],
    nameservers: Optional[List[str]] = None,
    timeout: float = 2.5,
) -> List[Record]:
    """Simple brute: resolve A/AAAA for word.domain"""
    out: List[Record] = []
    for w in words:
        w = w.strip()
        if not w:
            continue
        host = f"{w}.{domain}"
        out.extend(resolve_rr(host, "A", nameservers, timeout))
        out.extend(resolve_rr(host, "AAAA", nameservers, timeout))
    return out


def reverse_ptr(
    ip_or_range: str,
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
    limit: int = 1024,
) -> List[Record]:
    """
    Reverse PTR for:
    - single IP: "1.2.3.4"
    - range: "1.2.3.1-1.2.3.254"
    - CIDR: "1.2.3.0/24"
    limit: safety cap
    """
    res = _resolver(nameservers, timeout)
    out: List[Record] = []

    ips: List[str] = []

    if "-" in ip_or_range:
        s, e = ip_or_range.split("-", 1)
        start = ipaddress.ip_address(s.strip())
        end = ipaddress.ip_address(e.strip())
        cur = start
        while cur <= end and len(ips) < limit:
            ips.append(str(cur))
            cur = ipaddress.ip_address(int(cur) + 1)

    elif "/" in ip_or_range:
        net = ipaddress.ip_network(ip_or_range.strip(), strict=False)
        for ip in net.hosts():
            ips.append(str(ip))
            if len(ips) >= limit:
                break

    else:
        ips = [ip_or_range.strip()]

    for ip in ips:
        try:
            rev = dns.reversename.from_address(ip)
            ans = res.resolve(rev, "PTR")
            ttl = getattr(ans.rrset, "ttl", None)
            for r in ans:
                out.append(
                    {
                        "type": "PTR",
                        "name": str(rev).rstrip("."),
                        "ttl": ttl,
                        "address": ip,
                        "target": str(r.target).rstrip("."),
                    }
                )
        except Exception:
            pass

    return out


def standard_enum(
    domain: str,
    nameservers: Optional[List[str]] = None,
    timeout: float = 3.0,
    do_srv: bool = True,
    do_spf: bool = True,
    do_ptr: bool = False,
) -> List[Record]:
    """
    Best “high value” enumeration:
    SOA, NS (+checks), MX, A/AAAA, TXT/SPF, CAA, DNSKEY, wildcard, SRV, (optional PTR)
    """
    results: List[Record] = []

    # Wildcard
    results.append(check_wildcard(domain, nameservers, timeout))

    # Core record types
    for rt in ("SOA", "NS", "MX", "A", "AAAA", "TXT", "CAA", "DNSKEY"):
        results.extend(resolve_rr(domain, rt, nameservers, timeout))

    # NS checks (recursion/bindversion/nxdomain hijack)
    ns_targets = [
        r.get("target") for r in results if r.get("type") == "NS" and r.get("target")
    ]
    for ns in sorted(set(ns_targets)):
        # resolve NS to IP for direct query
        ns_a = resolve_rr(ns, "A", nameservers, timeout)
        for a in ns_a:
            ip = a.get("address")
            if not ip:
                continue
            results.append(check_recursive(ip, timeout))
            results.append(check_bindversion(ip, timeout))
            results.append(check_nxdomain_hijack(ip, timeout))

    # SRV
    if do_srv:
        results.extend(brute_srv(domain, nameservers, timeout))

    # SPF parse
    if do_spf:
        spf_nets = parse_spf_ips(domain, nameservers, timeout)
        if spf_nets:
            results.append(
                {"type": "SPF_IP_RANGES", "name": domain, "ranges": sorted(spf_nets)}
            )

    # PTR reverse for discovered A/AAAA (اختياري)
    if do_ptr:
        ips = {
            r.get("address")
            for r in results
            if r.get("type") in ("A", "AAAA") and r.get("address")
        }
        for ip in sorted(ips):
            # limit=1 per IP هنا (عشان يكون خفيف)
            results.extend(reverse_ptr(ip, nameservers, timeout, limit=1))

    return results


class PassiveDNSPlugin(PassivePlugin):
    name = "dns"
    description = (
        "DNS reconnaissance (SOA/NS/MX/A/AAAA/TXT/CAA/DNSKEY + wildcard + SRV + checks)"
    )

    def run(self, target: str, **kwargs) -> PluginOutput:
        timeout = float(kwargs.get("timeout", 3.0))
        do_srv = bool(kwargs.get("do_srv", True))
        do_spf = bool(kwargs.get("do_spf", True))
        do_ptr = bool(kwargs.get("do_ptr", False))

        logger.info(f"Running DNS Recon on {target}")
        output = PluginOutput(plugin=self.name)

        try:
            results = standard_enum(
                target,
                timeout=timeout,
                do_srv=do_srv,
                do_spf=do_spf,
                do_ptr=do_ptr,
            )

            # نخزن النتائج كما هي (dicts)
            for r in results:
                if isinstance(r, dict):
                    r["plugin"] = self.name
                output.results.append(r)

        except Exception as e:
            logger.error(f"DNS plugin error: {e}")
            output.errors.append(str(e))

        return output
