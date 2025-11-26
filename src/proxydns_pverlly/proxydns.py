# type: ignore

import os
import time
import logging
import ipaddress
from typing import Optional

import dns.resolver
from mitmproxy import http
from mitmproxy.connection import Connection

# retrieve config from environment variables
PROXYDNS_DNS_SERVERS    = os.environ.get("PROXYDNS_DNS_SERVERS").split(',')
PROXYDNS_VERBOSE        = os.environ.get("PROXYDNS_VERBOSE", "0") == "1"

# --------- CONFIG ----------
DNS_SERVERS = PROXYDNS_DNS_SERVERS      # seus DNS locais (ordem de tentativa)
DNS_TIMEOUT = 6.0                       # segundos
DNS_TTL_CACHE = 120.0                   # TTL simples da cache (segundos)
RESOLVE_IPV6 = False                    # true se quiser preferir AAAA
SKIP_SUFFIXES = (".onion",)             # domínios que NÃO devem ser resolvidos localmente

if PROXYDNS_VERBOSE:
    logging.info(f"[localdns] Config: DNS_SERVERS={DNS_SERVERS}, DNS_TIMEOUT={DNS_TIMEOUT}, DNS_TTL_CACHE={DNS_TTL_CACHE}, RESOLVE_IPV6={RESOLVE_IPV6}")

class TTLCache:
    def __init__(self, ttl: float):
        self.ttl = ttl
        self._d = {}

    def get(self, key):
        v = self._d.get(key)
        if not v:
            return None
        value, exp = v
        if time.time() > exp:
            self._d.pop(key, None)
            return None
        return value

    def set(self, key, value):
        self._d[key] = (value, time.time() + self.ttl)


_cache = TTLCache(DNS_TTL_CACHE)


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def local_resolve(host: str) -> Optional[str]:
    """Resolve hostname usando DNS_SERVERS (preferindo A ou AAAA) com cache TTL simples."""
    if is_ip(host):
        return host

    if any(host.endswith(suf) for suf in SKIP_SUFFIXES):
        return None

    cached = _cache.get((host, RESOLVE_IPV6))
    if cached:
        return cached

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    qtypes = ["AAAA", "A"] if RESOLVE_IPV6 else ["A", "AAAA"]
    for q in qtypes:
        try:
            ans = resolver.resolve(host, q, raise_on_no_answer=True)
            for rr in ans:
                ip = rr.to_text()
                _cache.set((host, RESOLVE_IPV6), ip)
                return ip
        except Exception:
            continue
    return None


class LocalDNSUpstream:
    """
    Estratégia:
      - Em HTTP (não CONNECT): antes de conectar, trocamos o destino para (IP, port).
        Mantemos o header Host original.
      - Em HTTPS (CONNECT): reescrevemos o authority para IP:port, e fixamos SNI no host original.
      - Tudo isso funciona mesmo com --mode upstream:... porque o upstream apenas cria
        o túnel TCP até o destino que indicarmos (IP), enquanto o TLS/SNI segue correto.
    """

    def load(self, loader):
        logging.info("[localdns] Add-on loaded. DNS_SERVERS=%s" % DNS_SERVERS)

    # HTTPS: intercepta o CONNECT antes de abrir o túnel ao upstream
    def http_connect(self, flow: http.HTTPFlow):
        original_host = flow.request.host
        original_port = flow.request.port

        if is_ip(original_host) or any(original_host.endswith(suf) for suf in SKIP_SUFFIXES):
            return  # não mexe

        ip = local_resolve(original_host)
        if not ip:
            logging.warning(f"[localdns] Failed to resolve {original_host}; delegating the work to the upstream.")
            return

        # Reescreve o CONNECT authority para IP:porta
        flow.request.host = ip
        flow.request.port = original_port

        # Garante que, quando for abrir TLS através do túnel, o SNI seja o hostname original
        flow.server_conn.sni = original_host
        flow.metadata["localdns_original_host"] = original_host

        logging.info(f"[localdns] CONNECT {original_host}:{original_port} -> {ip}:{original_port} (SNI={original_host})")

    # HTTP: antes de enviar a request (sem CONNECT)
    def requestheaders(self, flow: http.HTTPFlow):
        # Só aplica para HTTP direto (não CONNECT) e quando o destino é hostname
        if flow.request.method == "CONNECT":
            return

        original_host = flow.request.host
        original_port = flow.request.port

        if is_ip(original_host) or any(original_host.endswith(suf) for suf in SKIP_SUFFIXES):
            return

        ip = local_resolve(original_host)
        if not ip:
            logging.warning(f"[localdns] Failed to resolve {original_host}; delegating the work to the upstream.")
            return

        # Preserva o Host header original para roteamento virtual/HTTP/1.1
        if "Host" in flow.request.headers:
            flow.request.headers["Host"] = original_host
        else:
            flow.request.headers.add("Host", original_host)

        # Altera o destino TCP para IP
        flow.request.host = ip
        flow.request.port = original_port
        flow.metadata["localdns_original_host"] = original_host

        logging.info(f"[localdns] HTTP {original_host}:{original_port} -> {ip}:{original_port} (Host header preserved)")

    # Camada de conexão ao servidor (antes de abrir o socket via upstream)
    def serverconnect(self, conn: Connection):
        """
        Segurança extra: se ainda tivermos um hostname aqui, tenta resolver e trocar por IP,
        e força SNI = hostname original.
        """
        host, port = conn.address

        if is_ip(host) or any(str(host).endswith(suf) for suf in SKIP_SUFFIXES):
            return

        ip = local_resolve(host)
        if not ip:
            return

        # Mantém SNI correto:
        if not getattr(conn, "sni", None):
            conn.sni = host

        conn.address = (ip, port)
        logging.info(f"[localdns] serverconnect: {host}:{port} -> {ip}:{port} (SNI={conn.sni})")
