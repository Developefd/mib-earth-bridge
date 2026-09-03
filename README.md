# mib-earth-bridge
Restore Google Earth functionality on the MIB2 unit by running a proxy that relays requests back to original Google Keyhole servers correctly.
## How does it work?
It creates an HTTP server which acts as a clone (sort of) and modifies the requests sent by the MIB2 unit so that they don't get blocked by Google's Keyhole servers. Google blocks the token `QNX` in user agents from making requests to their servers, simply replacing it fixes the problem.
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
### 2. Hijack the DNS on the MMI for kh.google.com and point it to your server's IP. (The requests are always sent to port 80 via HTTP)
You can do this by modifying the `/etc/hosts` file in the MMX.
### 3. Hook the `de.audi.tghu.navi.app.online.ServiceListHandler.java` to always return a license.
```java
public void updateToken(String string, String string2, Object object) {
        ChoiceModelApp choiceModelApp;
        this.logChannel.log(10000000, "ServiceListHandler#updateToken(%1, %2, %3)", (Object)string, (Object)string2, (Object)object.toString());
        int n = -1;
        if (string == null || string2 == null) {
            this.logChannel.log(1000000, "ServiceListHandler#updateToken() - serviceID or token is NULL -> Ignore Update");
            return;
        }
        if (object != null) {
            try {
                n = ((Integer)object).intValue(); // This line didnt decompile correctly so make sure to copy this one too.
            }
            catch (ClassCastException classCastException) {
                this.logChannel.log(100000, "ServiceListHandler#updateToken() - Can not cast newValue to int! I'll set it to -1");
            }
        }
        if ((choiceModelApp = this.mapServiceIdToVisibilityModel(string, string2)) == null) {
            this.logChannel.log(100000, "ServiceListHandler#updateToken cannot map service %1 to a visibility model");
            return;
        }
        /* INJECTED */
        if ("service_dsi_satellitemaps".equals(string)) {
            n = 1;
        }
        /* END INJECTED */
	    choiceModelApp.setStatus(n);
        if (n == 3 || n == -1) {
            choiceModelApp.setValue(0);
            this.forceServiceShutDown(string);
        } else {
            choiceModelApp.setValue(1);
        }
        this.notifyGEVisibility(string);
    }
```
### 4. Restart the unit and switch to Google Earth view.
