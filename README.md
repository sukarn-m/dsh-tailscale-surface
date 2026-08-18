# dsh-tailscale-surface

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) plugin
that makes a **`tailscale serve`** surface in front of the web GUI a
first-class fact of the daemon: correct URL narration everywhere, working
remote Settings, and a same-origin home for auxiliary plugin UIs.

## Why

`dsh web` binds loopback (the GUI is effectively an RCE surface — the CLI
deliberately refuses `0.0.0.0`). Reaching it remotely through an SSH tunnel
works but is clumsy, and everything the runtime narrates about itself
(`DSH_WEB_URL`, the surface prompt, the URL line) points at `127.0.0.1` — an
origin a remote browser cannot resolve, so every user-facing link minted
from it is dead.

Fronting the daemon with `tailscale serve` fixes the transport
(tailnet HTTPS + verified identity) but stock DSH then 403s the whole
privileged RPC plane (Settings, credentials, model discovery, agent presets)
for remote users, because those methods are pinned to loopback-Host callers
and the proxy preserves the client's Host.

## What it does

1. **Discovers** the serve rule proxying this daemon (`tailscale status` /
   `serve status` via the `subprocess` service) and exports the canonical
   external URL:
   - `DSH_TS_URL` shell variable (agent shells, tools);
   - a system-prompt section that orients every model step to the external
     origin and forbids emitting loopback/LAN URLs to the user;
   - a `GET /__ts/status` route with the full health snapshot.
2. **Relays the 15 privileged `/api` methods** for **verified** operator
   logins. `tailscale serve` injects `Tailscale-User-Login` with the
   tailnet-verified login and *overwrites* any client-supplied value
   (verified empirically), so the header is unforgeable evidence of who is
   calling. The relay takes over those exact paths before the stock fence
   and dispatches them in-process via the `apiProxy` service — same call the
   real route makes, exact wire envelope. Direct local connections (no proxy
   headers) keep today's behavior.
   - This also closes, for these methods, a Host-spoofing path: serve
     forwards a client-supplied `Host` verbatim, so the stock loopback
     pinning is bypassable behind any Host-preserving proxy.
3. **`exposePath(prefix, handler)`** (service `tailscaleSurface`): plugins
   register auxiliary HTTP/WS surfaces on the main origin instead of binding
   fresh ports the remote browser can never reach.

## Install

```bash
# 1. copy the package into the profile module space
cp -r . ~/.dsh/profiles/node_modules/dsh-tailscale-surface

# 2. add the row to ~/.dsh/profiles/web/cordis.patch.yml
```

```yaml
- insert:
    - id: tailscale-surface
      name: dsh-tailscale-surface
      config:
        operatorLogins:
          - you@example.com        # your tailnet login (tailscale whois / serve headers)
        servePort: 8443            # the tailscale serve HTTPS port
        surfaceContext: true       # prompt section + DSH_TS_URL
```

3. Publish the surface (once, as the tailscale operator —
   `sudo tailscale set --operator=$USER` to manage without sudo):

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:3080
dsh web --host 127.0.0.1 --port 3080 \
  --trusted-host <your-node>.<tailnet>.ts.net:8443 <your-node>.<tailnet>.ts.net
```

4. Restart the daemon between sessions, then verify:

```bash
curl https://<your-node>.<tailnet>.ts.net:8443/__ts/status
```

## Configuration

| key | default | meaning |
|---|---|---|
| `operatorLogins` | `[]` | tailnet logins treated as operator-equivalent for privileged methods (relay inactive when empty) |
| `servePort` | `8443` | serve HTTPS port used when self-healing a missing rule (`ensureRule`) |
| `surfaceContext` | `true` | register the prompt section + `DSH_TS_URL` |

## Security notes

- The relay trusts `Tailscale-User-Login` **only because** the daemon binds
  loopback, making tailscaled the only reachable client. Any non-loopbind
  deployment must not reuse this design.
- Non-privileged RPCs (sessions, prompts, bash) remain reachable by anyone
  who can reach the serve port — restrict the port in your tailnet ACL to
  your own devices/users.
- Never put `funnel` in front of this GUI.

## Compatibility

Developed and verified against dsh `0.1.0-rc.7` and tailscale `1.102.2`.
The privileged method list is pinned to that version's
`PRIVILEGED_METHODS`; check it when upgrading dsh.

## License

MIT
