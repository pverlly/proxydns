# Usage
```sh
mitmproxy --listen-host 127.0.0.1 --listen-port 9000 \
--mode upstream:http://dc.decodo.com:10001 \
--upstream-auth user-xx-country-br:Jyyb \
-s src/proxydns_pverlly/proxydns.py \
--set connection_strategy=eager;
```
