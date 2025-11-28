# type: ignore
import os
import argparse
import asyncio
import logging

from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools import main

# setup logging
logging.basicConfig(
  level=logging.INFO,
  format="%(message)s",
  datefmt="[%X]",  
)

def custom(arg_string):
    return arg_string.split(',')

# create the parser
parser = argparse.ArgumentParser(description="Resolves DNS names using a custom server before routing traffic through a proxy.")
parser.add_argument("-lh", "--listen-host", type=str,     default="127.0.0.1", help="Local proxy listen host.")
parser.add_argument("-lp", "--listen-port", type=int,     default=9000, help="Local proxy listen port.")
parser.add_argument("-ds", "--dns-servers", type=custom,  default=["8.8.8.8"], help="List of DNS servers to use for resolution.")
parser.add_argument("-ra", "--remote-auth", type=str,     default=None, help="Remote Proxy authentication in the format username:password.")
parser.add_argument("-la", "--local-auth",  type=str,     default=None, help="Local mitmproxy authentication in the format username:password.")
parser.add_argument("-p", "--proxy",        type=str,     required=True, help="Remote Proxy server to forward traffic through (e.g., http://localhost:8080).")
parser.add_argument("-i", "--insecure", action="store_true", help="Do not verify upstream server SSL/TLS certificates.")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

# add usage example
parser.usage = """
    proxydns \\
        --listen-host localhost \\
        --listen-port 9000 \\
        --dns-servers 8.8.8.8,1.1.1.1 \\
        --proxy http://remote-proxy:8080 \\
        --remote-auth username:password \\
        --local-auth localuser:localpass \\
        --verbose
"""

args = parser.parse_args()


# store args in environment variables for access in proxydns.py
os.environ["PROXYDNS_DNS_SERVERS"] = ','.join(args.dns_servers)
os.environ["PROXYDNS_VERBOSE"] = "1" if args.verbose else "0"

print(f"+ Using DNS servers: {args.dns_servers}")
print(f"+ Forwarding traffic through proxy: {args.proxy}")

async def start_mitmproxy():
    from .proxydns import LocalDNSUpstream

    master = DumpMaster(options=None, with_dumper=True, with_termlog=True)

    # set options here
    # @NOTE ref: https://docs.mitmproxy.org/stable/concepts/options/
    master.options.set(f"mode=upstream:{args.proxy}")
    master.options.set(f"listen_host={args.listen_host}")
    master.options.set(f"listen_port={args.listen_port}")
    master.options.set(f"connection_strategy=eager")
    master.options.set(f"flow_detail=0")
    master.options.set(f"block_global=false")

    if args.remote_auth:
        master.options.set(f"upstream_auth={args.remote_auth}")
    if args.local_auth:
        master.options.set(f"proxyauth={args.local_auth}")
    if args.insecure:
        master.options.set(f"ssl_insecure=true")

    # master.addons.add(UpstreamAuth())
    master.addons.add(LocalDNSUpstream())

    try:
        await master.run()
    except KeyboardInterrupt:
        print("keyboard interrupt.")
        master.shutdown()

def main():
    try:
        asyncio.run(start_mitmproxy())
    except Exception as e:
        print("proxydns shutdown.")
        print(e)

if __name__ == "__main__":
    main()
