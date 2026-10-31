# dns-server

Fake DNS + HTTPS doorman so the PS5 User's Guide lands on your exploit host.
Node stdlib only - no dependencies, no build step. Works alongside the real
site: `node api/serve.js 8080`.

## The three pieces

| Port | Program | Job |
|---|---|---|
| udp 53 | `dns-server/dns.js` | allowlisted hosts (`manuals.playstation.net`) resolve to this machine's LAN IP, PlayStation/Sony domains NXDOMAIN (update + PSN blocker), everything else forwarded to a public upstream resolver (default 8.8.8.8) so the console can reach the real internet |
| tcp 443 (+80) | `dns-server/https.js` | doorman: the User's Guide insists on `https://manuals.playstation.net` port 443. Ends up here, shows the self-signed cert warning (accept once), then gets bounced to `http://<ip>:8080/` where the real exploit page lives |
| tcp 8080 | `api/serve.js` | the actual site (Jailbreak / Payloads buttons) and `/api/payload` delivery |

DNS can only change *the address*, never *the port* - that is why 443 needs its
own tiny server instead of you simply choosing one port for everything.

## Run (from the repo root)

```sh
sudo node dns-server/dns.js       # udp 53, needs root
sudo node dns-server/https.js     # tcp 443 + 80, needs root; generates
                                  # cert.pem/key.pem on first start
node api/serve.js 8080            # the real site
```

Port 53 and 443 are privileged; the root terminals only exist for that. Don't
run these as root habitually - if you'd rather not, `sudo setcap
'cap_net_bind_service=+ep' <path-to-node>` is an alternative.

First start of `https.js` auto-generates a 10-year self-signed certificate for
`manuals.playstation.net` (CN + SAN include your LAN IP). To do it manually:

```sh
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout dns-server/key.pem -out dns-server/cert.pem \
  -subj "/CN=manuals.playstation.net" \
  -addext "subjectAltName=DNS:manuals.playstation.net,IP:<your-LAN-IP>"
chmod 600 dns-server/key.pem
```

## Console setup

1. Find this machine's LAN IP: run `dns.js` once without flags, it prints the
   address it will answer with.
2. PS5: **Settings > Network > Settings > Set Up Internet Connection** > your
   network > **Options > Advanced > DNS Settings: Manual**, set **Primary DNS**
   to the machine IP, leave secondary `0.0.0.0`.
   (Leaving secondary empty is what makes this an *update blocker* too: PSN and
   update hostnames resolve to NXDOMAIN while your machine answers the DNS.)
3. **Settings > User's Guide, Health and Safety, and Other Information > User's
   Guide** - the certificate warning appears once, accept it, and the main
   page (Jailbreak / Payloads buttons) takes over from `api/serve.js`.

Firewalls must let the LAN reach udp/53 and tcp/443, 80, 8080 (and any
outbound connection *from* this machine to the console's tcp/9021 at payload
time).

## Options

```text
dns.js    [--ip <addr>]        answer with this address  (default: auto LAN IP)
          [--port <n>]         UDP port                  (default: 53)
          [--upstream <addr>]  resolver non-Sony queries are forwarded to
                               (default: 8.8.8.8)
          [--no-block-psn]     answer PlayStation/Sony names with the IP too
https.js  [--ip <addr>]        address in redirects      (default: auto LAN IP)
          [--port <n>]         HTTPS port                (default: 443)
          [--http-port <n>]    HTTP port                 (default: 80; 0 disables)
          [--target-port <n>]  api/serve.js port         (default: 8080)
          [--cert <p>] [--key <p>]                       (default: cert.pem/key.pem here)
```

Useful flags for local testing without root: `--port 5353`, `--port 8443
--http-port 0 --target-port 9000`, etc.

## Known caveats

- UDP only: DNS over TCP/53 is not implemented. Consoles ship their queries by
  UDP first; every self-host guide relies on this.
- After a console reboot the accepted-certificate state for the appcache can go
  stale, which is why appcache manifest requests are answered 404 instead of
  state; cold-boot the console and accept the warning again if the old page
- The cert generation path expects `openssl` on PATH; without it, the exact
  manual command is printed instead of half-broken files.
- `notplaystation.<anything>.com` resolves normally (blocking is per-label, not
  substring), mid-domain `playstation` still matches, so `update.playstation.net`
  gets dropped.
