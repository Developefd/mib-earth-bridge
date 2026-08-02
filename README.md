# GoogleEarthMIB2
Restore Google Earth functionality on the MIB2 unit by running a proxy that relays requests back to original Google Keyhole servers correctly.
## How does it work?
## How do I use it?
### 1. Run the proxy server.
```
Usage: node ge_server.js [options]

  --port N            listen port (default 80; the car will use 80)
  --bind ADDR         default 0.0.0.0
  --version V         client version to advertise (default 7.1.8.3036)
  --os-token T        replaces the literal "QNX" in the UA, which Google 403s
                      (default Linux) -- this is the rewrite that matters
  --force-ua          also set a User-Agent when the client sends none
  --upstream-ip IP    pin the real kh.google.com IP instead of resolving
  --cache-dir DIR     default ge_cache
  --no-cache          disable caching
  --cache-max-mb N    0 for unlimited (default 2048)
  --dbroot-ttl SEC    seconds to cache dbRoot; 0 = never cache (default 86400)
  --timeout SEC       upstream timeout, default 30
  --debug             on any non-200 upstream reply, dump the full outgoing
                      request headers and a preview of the response body
```
### 2. Hijack the DNS on the MMI for kh.google.com and point it to your server's IP. (The requests are always sent to port 80)
You can do this by modifying the `/etc/hosts` file in the MMX.
### 4. Restart the unit and switch to Google Earth view.
