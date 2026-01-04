"""
Full WHOIS passive plugin for Crow Recon OSINT Framework
Fixed BaseRecord extra fields issue & improved parsing
"""

import socket
from typing import List, Optional

from crow.core.bases import PassivePlugin
from crow.core.logger import logger
from crow.core.models import BaseRecord, PluginOutput


# ============================================
# WHOIS NIC Client (unchanged from original)
# ============================================
class NICClient(object):
    ABUSEHOST = "whois.abuse.net"
    NICHOST = "whois.crsnic.net"
    INICHOST = "whois.networksolutions.com"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    ANICHOST = "whois.arin.net"
    LNICHOST = "whois.lacnic.net"
    RNICHOST = "whois.ripe.net"
    PNICHOST = "whois.apnic.net"
    MNICHOST = "whois.ra.net"
    QNICHOST_TAIL = ".whois-servers.net"
    SNICHOST = "whois.6bone.net"
    BNICHOST = "whois.registro.br"
    NORIDHOST = "whois.norid.no"
    IANAHOST = "whois.iana.org"
    GERMNICHOST = "de.whois-servers.net"
    DEFAULT_PORT = "nicname"
    WHOIS_SERVER_ID = "Whois Server:"
    WHOIS_ORG_SERVER_ID = "Registrant Street1:Whois Server:"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02
    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST]

    def __init__(self):
        self.use_qnichost = False

    def findwhois_server(self, buf, hostname):
        nhost = None
        parts_index = 1
        start = buf.find(NICClient.WHOIS_SERVER_ID)
        if start == -1:
            start = buf.find(NICClient.WHOIS_ORG_SERVER_ID)
            parts_index = 2
        if start > -1:
            end = buf[start:].find("\n")
            whois_line = buf[start : end + start]
            whois_parts = whois_line.split(":")
            nhost = whois_parts[parts_index].strip()

        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break

        return nhost

    def whois(self, query, hostname, flags):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, 43))

        if hostname == NICClient.GERMNICHOST:
            s.send(
                "-T dn,ace -C US-ASCII ".encode("utf-8")
                + query.encode("utf-8")
                + b"\r\n"
            )
        else:
            s.send((query + "\r\n").encode("utf-8"))

        response = b""
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break

        s.close()
        nhost = None

        if flags & NICClient.WHOIS_RECURSE and nhost is None:
            nhost = self.findwhois_server(
                response.decode("utf-8", errors="ignore"), hostname
            )

        if nhost is not None:
            response += self.whois(query, nhost, 0)

        return response.decode("utf-8", errors="ignore")

    def choose_server(self, domain):
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        pos = domain.rfind(".")
        if pos == -1:
            return None
        tld = domain[pos + 1 :]
        if tld[0].isdigit():
            return NICClient.ANICHOST
        return tld + NICClient.QNICHOST_TAIL

    def whois_lookup(self, options, query_arg, flags):
        if options is None:
            options = {}

        if (options.get("whoishost") is None) and (options.get("country") is None):
            self.use_qnichost = True
            options["whoishost"] = NICClient.NICHOST
            if not (flags & NICClient.WHOIS_QUICK):
                flags |= NICClient.WHOIS_RECURSE

        if options.get("country") is not None:
            return self.whois(
                query_arg, options["country"] + NICClient.QNICHOST_TAIL, flags
            )

        elif self.use_qnichost:
            nichost = self.choose_server(query_arg)
            if nichost:
                return self.whois(query_arg, nichost, flags)

        return self.whois(query_arg, options["whoishost"], flags)


# ============================================
# WHOIS Record Model (Fix: allow extra fields)
# ============================================
class WHOISRecord(BaseRecord):
    model_config = {"extra": "allow"}  # FIX: allow all fields in JSON output

    domain: str
    registrant: Optional[str] = None
    emails: List[str] = []
    creation_date: Optional[str] = None
    name_servers: List[str] = []


# ============================================
# Plugin Class
# ============================================
class WhoisPlugin(PassivePlugin):
    name = "whois"
    description = "Full-featured WHOIS lookup (original logic intact)"

    def run(self, target: str, **kwargs) -> PluginOutput:
        logger.info(f"[{self.name}] querying WHOIS for {target}")
        results: List[BaseRecord] = []
        errors: List[str] = []

        nic = NICClient()
        flags = 0
        options = kwargs.get("options", {})

        try:
            raw = nic.whois_lookup(options, target, flags)

            # ===== Parsing =====
            emails, ns = [], []
            registrant, cre_date = None, None

            for line in raw.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue

                key, val = line.split(":", 1)
                key = key.lower().strip()
                val = val.strip()

                if "email" in key:
                    emails.append(val)
                elif "name server" in key or "nserver" in key:
                    ns.append(val)
                elif "registrant" in key and not registrant:
                    registrant = val
                elif any(
                    k in key for k in ("creation date", "created", "registered on")
                ):
                    cre_date = val

            record = WHOISRecord(
                plugin=self.name,
                domain=target,
                registrant=registrant,
                emails=emails,
                creation_date=cre_date,
                name_servers=ns,
            )

            results.append(record)

        except Exception as exc:
            logger.exception(f"[{self.name}] WHOIS ERROR")
            errors.append(str(exc))

        return PluginOutput(plugin=self.name, results=results, errors=errors)
