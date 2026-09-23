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
| `settingsMirrorPatch` | `true` | force the dsh-client-ui-settings settings mirror to use `'host'` persistence for this surface. Compensates for the upstream loopback gate (Settings > Models otherwise shows "settings are unavailable in this browser" because the browser-side mirror stays in a terminal `unavailable` state, even though the server-side `/api/settings/describe` RPC accepts the authenticated request). Self-disables the moment upstream removes the buggy pattern from `dsh-client-ui-settings`. See `Settings > Models conditional patch` below. |

## Security notes

- The relay trusts `Tailscale-User-Login` **only because** the daemon binds
  loopback, making tailscaled the only reachable client. Any non-loopbind
  deployment must not reuse this design.
- Non-privileged RPCs (sessions, prompts, bash) remain reachable by anyone
  who can reach the serve port — restrict the port in your tailnet ACL to
  your own devices/users.
- Never put `funnel` in front of this GUI.

## Settings > Models conditional patch

Upstream `@deepseek-ai/dsh-client-ui-settings` 0.1.5-rc.2 selects the
settings-mirror persistence from the browser's loopback fact:
`persistence = $host.isLoopback ? "host" : "memory"`. For a non-loopback
host the mirror is initialised to `status: "unavailable"` and its `load()`
and `ensure()` early-return — the wire read never happens, so the Settings
> Models page falls back to the literal string "settings are unavailable in
this browser". The server-side `/api/settings/describe` RPC does accept the
authenticated request from this surface (dsh web's own launch-token → signed
cookie + `--trusted-host` fence authorizes it), so the only thing standing
between the user and a working remote Settings > Models is the browser-side
loopback gate.

When `settingsMirrorPatch: true` (default), this plugin:

1. registers a longest-prefix-wins `/plugins/??@deepseek-ai/dsh-client-ui-settings`
   route on the web server. It calls the upstream `clientModules.bundleResource`
   synchronously and rewrites the literal pattern
   `const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";` to
   `const persistence = "host";` in the served body. Source maps, non-JS
   bodies, HEAD responses, and URLs whose pattern no longer matches pass
   through unchanged.
2. registers a `webServer.tapIndex` that rewrites the affected entry's `rev`
   in `window.__DSH_BOOT__` to a `-patched` suffix. This forces the browser's
   1-year immutable cache for the old URL to miss, so the patch takes effect
   on the next page load — no hard-refresh required.

**Self-disabling.** Both pieces only act when the upstream pattern is still
present. The moment upstream `@deepseek-ai/dsh-client-ui-settings` drops or
rewrites that line (e.g. adopting the config-field fix proposed in
[deepseek-harness discussion #5829](https://github.com/deepseek-ai/deepseek-harness/discussions/5829)),
the route still claims the prefix but hands the body through unchanged and
the tap rewrite is a no-op (`-patched` already on the URL). Set
`settingsMirrorPatch: false` to opt out manually.

**Trust boundary.** Forcing `'host'` persistence on this surface is
intentional only because this surface is already gated by dsh web's
launch-token → signed cookie + `--trusted-host` fence. Do not enable this
patch on a deployment where the loopback identity is meaningful (e.g.
binding `dsh web` to `0.0.0.0` or fronting it with anything less strict than
Tailscale identity + tailnet-ACL-restricted serve).

## Compatibility

Developed and verified against dsh `0.1.0-rc.7` and tailscale `1.102.2`.
The privileged method list is pinned to that version's
`PRIVILEGED_METHODS`; check it when upgrading dsh.

## License

MIT
