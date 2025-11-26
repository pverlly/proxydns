# dnspython
import dns.resolver
import ipaddress
import time
from typing import Optional


# --------- CONFIG ----------
DNS_SERVERS = ["8.8.8.8"]     # seus DNS locais (ordem de tentativa)
DNS_TIMEOUT = 6.0                           # segundos
DNS_TTL_CACHE = 120.0                       # TTL simples da cache (segundos)
RESOLVE_IPV6 = False                        # true se quiser preferir AAAA
SKIP_SUFFIXES = (".onion",)                 # domínios que NÃO devem ser resolvidos localmente
# ---------------------------

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


response = local_resolve("ip-api.com")

print(response)
