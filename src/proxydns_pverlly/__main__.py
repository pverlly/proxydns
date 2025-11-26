# type: ignore
import os
import argparse
from mitmproxy.tools.main import mitmdump

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

def main():
    mitmproxy_args = [
        "--listen-host", f"{args.listen_host}",
        "--listen-port", f"{args.listen_port}",
        "--upstream-auth", f"{args.remote_auth}" if args.remote_auth else "",
        "--proxyauth", f"{args.local_auth}" if args.local_auth else "",
        "--mode", f"upstream:{args.proxy}",
        "--set", f"connection_strategy=eager",
        "-s", "src/proxydns_pverlly/proxydns.py",
    ]

    if args.verbose:
        print("MITMproxy arguments:")
        print(mitmproxy_args)

    mitmdump(mitmproxy_args)

if __name__ == "__main__":
    main()
