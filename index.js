// dsh-tailscale-surface — a Cordis plugin for the DeepSeek Harness web
// profile that makes a `tailscale serve` surface a first-class fact of the
// daemon.
//
// What it does:
//  - discovers the `tailscale serve` rule fronting this daemon and exports the
//    canonical external URL (DSH_TS_URL shell variable, system-prompt section,
//    /__ts/status route);
//  - exposePath(): register auxiliary surfaces on the main origin instead of
//    binding unreachable new ports;
//  - stable login URL: dsh web 0.1.2-rc.1 authenticates the browser with a
//    one-time launch token (?token=, printed to the daemon log, rotates every
//    restart) exchanged for a 30-day signed cookie. To avoid hunting the log,
//    this plugin registers /login (config.loginPath) which redirects to
//    /?token=<current token>, reading the live launch token from the
//    `connection` service. Bookmark it on each device; after a cookie lapse a
//    single visit to /login re-mints the cookie.
//
// Ported from the 0.1.0-rc.7 build to the republished 0.1.2-rc.1 architecture.
// The old build also hand-rolled an identity-gated relay for 15 privileged
// /api methods (settings.*, credentials.*, agentPreset.*, host.*,
// llm.discoverModels) over the `apiProxy` service. That service is GONE in
// 0.1.2-rc.1: the web carrier now does its own auth (a one-time launch token
// exchanged for an HMAC-signed HttpOnly SameSite=Strict cookie) plus a
// Host/Origin browser-trust fence driven by `dsh web --trusted-host`. That
// built-in auth already authorizes AND secures remote privileged access over
// the tailscale surface — strictly stronger than the old Tailscale-User-Login
// header allowlist (a signed cookie cannot be forged by a malicious local
// page). The relay is therefore obsolete and has been removed; remote Settings
// works through the built-in auth. Verified 2026-09-09:
//   POST https://<surface>/api/settings/describe (cookie) -> 200 {ok:true}
// If the dsh web carrier ever drops the `--trusted-host` fence or the cookie
// auth, this plugin's DSH_TS_URL/prompt guidance still holds, but remote
// privileged RPCs would need re-securing.
import z from '@deepseek-ai/schemastery'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { scrubbedParentEnv } from '@deepseek-ai/dsh-subprocess'

export const name = 'tailscale-surface'

// Services read directly as ctx.<name>. Only webServer is read directly;
// shellEnv and systemPrompt are used through scoped ctx.inject([...]) below,
// which is the 0.1.2-rc.1 pattern (mirrors dsh-web-app). The old build also
// injected subprocess/timer/apiProxy; those are gone now (tailscale is spawned
// via node:child_process; the apiProxy relay is subsumed by built-in auth).
export const inject = ['webServer']

export const Config = z.object({
  // operatorLogins was consumed by the removed relay; kept (ignored) so an
  // existing cordis.patch.yml config block stays valid on the port.
  operatorLogins: z.array(String).default([]),
  servePort: z.natural().max(65535).default(8443),
  surfaceContext: z.boolean().default(true),
  // Exact route that 302-redirects to /?token=<live launch token> so a
  // bookmarked device can re-authenticate without the daemon log.
  loginPath: z.string().default('/login'),
  login: z.boolean().default(true),
  // Also claim the exact '/' route so an unauthenticated browser visiting the
  // bare root (401 "reopen the URL" in the stock build) is bounced to /login
  // instead. When enabled, /login is the whole login flow end to end.
  // Disable to restore the stock 401-at-root behavior.
  root: z.boolean().default(true),
  // Path to dist/index.html for rendering the authenticated index from our
  // '/' route. Empty = resolve @deepseek-ai/dsh-web-frontend via require, the
  // same file the daemon's own frontend-static plugin serves (profile tree
  // symlinks to the shared npx cache, so it's the same physical file).
  distIndex: z.string().default(''),
})

// Run one `tailscale` CLI invocation and resolve { code, out, err }. Never
// rejects: a timeout / spawn failure resolves to a nonzero code so the
// discovery path treats it like any other "tailscale unavailable" state.
// Uses node:child_process directly (dsh-web-app does the same for its browser
// opener) rather than the `subprocess` service, whose handle shape changed
// between the 0.1.0-rc.7 and 0.1.2-rc.1 builds.
function runCli(args, timeoutMs) {
  return new Promise((resolve) => {
    execFile('tailscale', args, {
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
      env: scrubbedParentEnv(),
    }, (error, stdout, stderr) => {
      const out = Buffer.isBuffer(stdout) ? stdout.toString('utf8') : (stdout || '')
      const errText = Buffer.isBuffer(stderr) ? stderr.toString('utf8') : (stderr || '')
      let code = error ? 1 : 0
      if (error) {
        if (typeof error.code === 'number') code = error.code
        else if (error.killed) code = 124 // timed out
      }
      resolve({ code, out, err: errText })
    })
  })
}

export function apply(ctx, config) {
  const state = {
    fqdn: null, tailnetIP: null, certOK: false, backendPort: null,
    serveHostPort: null, rulePresent: null, serveManageable: null,
    externalUrl: null, lastError: null, checkedAt: null,
  }
  const exposed = []

  function snapshot() {
    return {
      externalUrl: state.externalUrl, fqdn: state.fqdn, tailnetIP: state.tailnetIP,
      certOK: state.certOK, backendPort: state.backendPort, serveHostPort: state.serveHostPort,
      rulePresent: state.rulePresent, serveManageable: state.serveManageable,
      exposedPaths: exposed.slice(),
      lastError: state.lastError, checkedAt: state.checkedAt,
    }
  }

  async function health() {
    try {
      const st = await runCli(['status', '--json'], 10000)
      if (st.code !== 0) throw new Error('tailscale status failed: ' + st.err.trim())
      const d = JSON.parse(st.out)
      const self = d.Self || {}
      state.fqdn = String(self.DNSName || '').replace(/\.$/, '')
      state.tailnetIP = (self.TailscaleIPs || [])[0] || null
      state.certOK = (d.CertDomains || []).indexOf(state.fqdn) !== -1
      if (state.fqdn === '') throw new Error('no tailscale identity (Self.DNSName empty)')
      state.backendPort = ctx.webServer.port
      const sv = await runCli(['serve', 'status', '--json'], 10000)
      state.rulePresent = false
      state.serveHostPort = null
      state.externalUrl = null
      if (sv.code !== 0) {
        state.serveManageable = false
        throw new Error('tailscale serve status failed: ' + sv.err.trim())
      }
      state.serveManageable = true
      const cfg = JSON.parse(sv.out)
      const backend = 'http://127.0.0.1:' + state.backendPort
      // Classic (non-service) serve keeps Web at the top level; service-based
      // tailnets nest it under Services.<name>.Web. Merge both so rule
      // discovery works on either layout.
      const web = {}
      const svcMap = cfg.Services || {}
      Object.keys(svcMap).forEach((svcName) => {
        const svcWeb = (svcMap[svcName] || {}).Web || {}
        Object.keys(svcWeb).forEach((hostPort) => {
          if (!(hostPort in web)) web[hostPort] = svcWeb[hostPort]
        })
      })
      Object.keys(cfg.Web || {}).forEach((hostPort) => {
        if (!(hostPort in web)) web[hostPort] = cfg.Web[hostPort]
      })
      Object.keys(web).forEach((hostPort) => {
        const handlers = (web[hostPort] || {}).Handlers || {}
        Object.keys(handlers).forEach((path) => {
          if ((handlers[path] || {}).Proxy === backend) {
            state.rulePresent = true
            state.serveHostPort = hostPort
            state.externalUrl = 'https://' + hostPort + (path === '/' ? '' : path)
          }
        })
      })
      state.lastError = null
    } catch (e) {
      state.lastError = e && e.message ? e.message : String(e)
    }
    state.checkedAt = new Date().toISOString()
    return snapshot()
  }

  let pending = null
  function refresh() {
    if (pending === null) {
      pending = health().then(
        (snap) => { pending = null; return snap },
        (e) => { pending = null; throw e },
      )
    }
    return pending
  }

  const surface = {
    snapshot,
    refresh,
    ensureRule() {
      return refresh().then((snap) => {
        if (snap.rulePresent) return snap
        const port = snap.backendPort === null ? 3080 : snap.backendPort
        return runCli(['serve', '--bg', '--https=' + String(config.servePort), 'http://127.0.0.1:' + String(port)], 15000).then((r) => {
          if (r.code !== 0) throw new Error('serve rule add failed: ' + (r.err || r.out).trim())
          return health()
        })
      })
    },
    exposePath(prefix, handler) {
      const dispose = ctx.webServer.register({ kind: 'prefix', path: prefix, handler })
      exposed.push(prefix)
      ctx.effect(() => () => {
        const i = exposed.indexOf(prefix)
        if (i !== -1) exposed.splice(i, 1)
        dispose()
      }, 'tailscale-surface: expose ' + prefix)
      const base = state.externalUrl === null
        ? 'http://127.0.0.1:' + String(state.backendPort ?? 3080)
        : state.externalUrl
      return { url: base + prefix, dispose }
    },
  }
  ctx.provide('tailscaleSurface', surface)

  if (config.surfaceContext) {
    // DSH_TS_URL shell variable for agent shells/tools. Uses ctx.inject (the
    // 0.1.2-rc.1 pattern dsh-web-app uses for shellEnv) rather than a bare
    // ctx.get so it only registers when the shellEnv service is present.
    ctx.inject(['shellEnv'], (runtimeCtx) => {
      runtimeCtx.effect(() => runtimeCtx.shellEnv.register({
        name: 'tailscale-surface',
        variables: {
          DSH_TS_URL: {
            description: "Canonical tailnet HTTPS URL of this DSH GUI (Tailscale serve surface). Prefer over DSH_WEB_URL for user-facing links: the user's browser cannot reach this host's loopback.",
          },
        },
        resolve: () => (state.externalUrl === null ? {} : { DSH_TS_URL: state.externalUrl }),
      }), 'tailscale-surface: shellEnv')
    })
    // System-prompt section so the agent knows the canonical remote URL and
    // the auth model for remote privileged access.
    ctx.inject(['systemPrompt'], (promptCtx) => {
      promptCtx.effect(() => promptCtx.systemPrompt.section({
        name: 'app:tailscale-surface',
        order: -97,
        text: () => {
          if (state.externalUrl === null) {
            return "Tailscale surface: not detected (yet). Until it is, treat every URL you would hand the user as suspect: their browser cannot resolve this host's 127.0.0.1 or LAN addresses. Check /__ts/status."
          }
          return 'The user reaches this GUI remotely through Tailscale at ' + state.externalUrl + ". Their browser CANNOT resolve this host's 127.0.0.1, localhost, or LAN addresses. Every user-facing URL you emit or a plugin mints MUST start with " + state.externalUrl + ' (also in env DSH_TS_URL) — never http://127.0.0.1:PORT, localhost, or LAN IPs. To add an auxiliary UI or endpoint, register a same-origin route via the tailscaleSurface service (exposePath) or the webServer service instead of binding a new port; a fresh port is unreachable to the user. Remote access — including privileged Settings RPCs (settings.*, credentials.*, agentPreset.*, host.*, llm.discoverModels) — is authorized by dsh web\'s own authentication: the browser completes a one-time launch-token login that mints a signed session cookie, and the daemon accepts this Tailscale hostname via its --trusted-host fence. If the user hits a 401 (their session cookie has lapsed or is new), tell them to open the stable re-login URL ' + state.externalUrl + '/login once — it mints a fresh cookie without needing the daemon log. A 403 means this Tailscale hostname is not in the daemon\'s trusted-host list.'
        },
      }), 'tailscale-surface: prompt section')
    })
  }

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/__ts/status',
    handler: (req, res) => {
      if (req.method !== 'GET') { res.writeHead(405); res.end(); return }
      const body = JSON.stringify(snapshot())
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(new TextEncoder().encode(body).length) })
      res.end(body)
    },
  }), 'tailscale-surface: status route')

  // Both routes read the `connection` service, so register them in one scope.
  //
  // /login — stable re-authentication URL. dsh web's launch token rotates on
  //   every restart and is otherwise only visible in the daemon log, so a
  //   bookmarked device can't re-login after its 30-day cookie lapses. This
  //   route reads the live launch token from the `connection` service and
  //   302-redirects to /?token=<token> (relative, so the browser stays on the
  //   host it used to reach /login and the cookie is minted for that
  //   authority). Visiting it is the whole login flow.
  //
  // / — bounce unauthenticated visitors to /login. The stock build serves the
  //   SPA index here via the webserver fallback seat, gating it with a bare
  //   401 "reopen the URL" when the cookie is absent. By claiming an exact
  //   '/' route (which takes precedence over the fallback seat) we keep the
  //   token-exchange path intact (delegated to connection.authorizeIndex,
  //   which mints the cookie and 303s) but replace the 401 for plain
  //   unauthenticated GETs with a 302 to /login. The index itself is rendered
  //   for already-authenticated requests the same way frontend-static does
  //   (same dist/index.html, same base-href + index-injection taps).
  ctx.inject(['connection'], (connCtx) => {
    const conn = connCtx.connection

    if (config.login) {
      connCtx.effect(() => connCtx.webServer.register({
        kind: 'exact',
        path: config.loginPath,
        handler: (req, res) => {
          if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end(); return }
          let token
          try {
            token = new URL(conn.authenticatedUrl('http://127.0.0.1/')).searchParams.get('token')
          } catch (e) {
            res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: connection service unavailable; cannot mint login token')
            return
          }
          if (typeof token !== 'string' || token.length === 0) {
            res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: connection service returned no launch token')
            return
          }
          res.writeHead(302, {
            'location': '/?token=' + encodeURIComponent(token),
            'cache-control': 'no-store',
            'referrer-policy': 'no-referrer',
          })
          res.end()
        },
      }), 'tailscale-surface: login route')
    }

    if (config.root) {
      // Locate dist/index.html. Prefer an explicit path; otherwise resolve
      // @deepseek-ai/dsh-web-frontend the same way dsh-web-app does. The
      // profile tree symlinks @deepseek-ai/* into the shared npx cache, so
      // this is the identical file the daemon's frontend-static serves — no
      // risk of serving a stale manifest.
      let distIndex
      try {
        if (config.distIndex) {
          distIndex = config.distIndex
        } else {
          const req2 = createRequire(import.meta.url)
          distIndex = join(dirname(req2.resolve('@deepseek-ai/dsh-web-frontend/package.json')), 'dist', 'index.html')
        }
      } catch (e) {
        distIndex = null
      }
      const renderIndex = async () => {
        const raw = await readFile(distIndex, 'utf8')
        return connCtx.webServer.renderIndex(raw).replace(/<head(?:\s[^>]*)?>/i, (open) => open + '<base href="/">')
      }

      connCtx.effect(() => connCtx.webServer.register({
        kind: 'exact',
        path: '/',
        handler: async (req, res) => {
          if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); res.end(); return }
          let url
          try { url = new URL(req.url ?? '/', 'http://x') } catch { url = new URL('/', 'http://x') }
          const tokens = url.searchParams.getAll('token')
          // Token-exchange path: let the daemon's own auth mint the cookie and
          // 303 to clean '/' (or 401 on a bad token) — identical to stock.
          if (tokens.length > 0) {
            conn.authorizeIndex(req, res)
            return
          }
          // No token: probe the Host fence + cookie without writing anything.
          // undefined => authenticated; 401 => no valid cookie; 403 => host not
          // trusted. Bounce anything not authenticated to the stable login URL.
          let rejection
          try {
            rejection = conn.requestRejection({ headers: req.headers, method: req.method })
          } catch (e) {
            res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: connection service unavailable; cannot verify session')
            return
          }
          if (rejection !== void 0) {
            res.writeHead(302, {
              'location': config.loginPath,
              'cache-control': 'no-store',
              'referrer-policy': 'no-referrer',
            })
            res.end()
            return
          }
          // Authenticated: render the SPA index exactly as frontend-static does.
          if (distIndex === null) {
            res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: cannot resolve dist/index.html; frontend will not load')
            return
          }
          try {
            const body = await renderIndex()
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
            res.end(body)
          } catch (e) {
            res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: failed to render index: ' + (e && e.message ? e.message : e))
          }
        },
      }), 'tailscale-surface: root route')
    }
  })

  refresh().then(
    (snap) => console.log('tailscale-surface: ' + (snap.externalUrl === null ? 'no serve rule found for this daemon' : snap.externalUrl) + ' (remote privileged RPCs ride dsh web token/cookie auth + --trusted-host fence)'),
    () => {},
  )
}
