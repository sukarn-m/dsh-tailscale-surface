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
import crypto from 'node:crypto'
import os from 'node:os'
import { scrubbedParentEnv } from '@deepseek-ai/dsh-subprocess'

export const name = 'tailscale-surface'

// Where the /login passcode's scrypt hash lives. Created once out-of-band by
// gen_auth.js (see repo notes); 0600, outside the git tree. Re-read on every
// POST so a rotation takes effect on the next request without a restart.
const AUTH_FILE = join(os.homedir(), '.dsh', 'profiles', 'tailscale-surface', 'auth.json')

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
  // Force the dsh-client-ui-settings settings mirror to use 'host' persistence
  // for this tailnet browser. Upstream 0.1.5-rc.2 picks 'memory' for every
  // non-loopback origin and never reads the wire, so Settings > Models shows
  // "settings are unavailable in this browser" even though the server-side
  // /api/settings/describe RPC accepts the request from this exact surface
  // (dsh web's own token/cookie auth + --trusted-host fence authorizes it;
  // remote Settings works through that built-in auth, verified upstream in
  // dsh-tailscale-surface#30-31). The patch claims the plugin bundle route
  // for @deepseek-ai/dsh-client-ui-settings, replaces the persistence
  // selection in the served JS, and self-disables the moment upstream no
  // longer ships the buggy pattern (the route still claims the prefix but
  // hands through unchanged). A tapIndex on the index also rewrites the
  // affected entry's rev in __DSH_BOOT__ to a -patched suffix so any
  // browser with the unpatched bundle still in its 1-year immutable cache
  // sees a fresh URL on its next page load — no hard-refresh required.
  // Set false to opt out (e.g. while reproducing the upstream bug).
  settingsMirrorPatch: z.boolean().default(true),
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

  // Settings > Models conditional patch (see Config.settingsMirrorPatch).
  // Plugin bundles are served by the client-modules service at
  // /plugins/??<pkg>/client.js[.map]&rev=<hash>. The combo concatenates
  // several files but preserves source verbatim (only sourceURL/sourceMappingURL
  // trailers are stripped), so the literal pattern below is searchable in
  // any combo that includes @deepseek-ai/dsh-client-ui-settings.
  //
  // Earlier draft registered a longest-prefix-wins webServer route for the
  // full /plugins/??@deepseek-ai/dsh-client-ui-settings prefix, but that
  // never matched: webServer.match() keys on `pathname` (everything before
  // the first `?`), which strips the `??@…` portion into the query string,
  // so the longest prefix over the stripped pathname is just `/plugins`
  // and the upstream /plugins route always wins. The fix is to wrap the
  // upstream `bundleResource(method, url)` itself — it receives the full
  // `req.url` (query string included), runs the resource-table lookup,
  // and returns the body; an instance-property override on
  // clientModules shadows the prototype method that both fetchBundle() and
  // the serveBundle route handler call via `this.bundleResource(...)`.
  //
  // Source maps, non-JS bodies, HEAD requests, and bundles whose pattern
  // no longer matches pass through unchanged.
  if (config.settingsMirrorPatch) {
    const SETTINGS_PKG = '@deepseek-ai/dsh-client-ui-settings'
    const PATCH_PATTERN = /const persistence = ctx\.remote\.\$host\.isLoopback \? "host" : "memory";/
    const PATCH_REPLACE = 'const persistence = "host";'
    // Match the entry/batch URL property whose path begins with the dsh-
    // client-ui-settings combo segment (so it catches both single-plugin
    // entries and multi-plugin combos that include it, but never a sibling
    // like dsh-client-ui-settings-models). The rev query sits at the end
    // of the URL string; rewrite it to a -patched suffix so the browser
    // sees a URL it has never cached (no immutable-cache miss), then fall
    // through to the bundleResource wrap below. Idempotent: a second pass
    // leaves already-rewritten URLs alone.
    const BOOT_URL_PATTERN = /"url":"(\/plugins\/\?\?@deepseek-ai\/dsh-client-ui-settings\/[^"]+)"/g
    const REV_PATTERN = /([?&])rev=([^&"\\]*)/

    ctx.inject(['webServer', 'clientModules'], (patchCtx) => {
      let patchObserved = false

      // Bump the rev in the served __DSH_BOOT__ payload so the browser's
      // existing immutable cache for the bundle URL does not keep serving
      // the unpatched bytes it fetched before this plugin started
      // intercepting. Without this, the user would have to hard-refresh
      // once after installing the plugin.
      patchCtx.effect(() => patchCtx.webServer.tapIndex((html) => {
        return html.replace(BOOT_URL_PATTERN, (match, url) => {
          if (url.includes('-patched')) return match
          const bumped = url.replace(REV_PATTERN, (_, sep, rev) => `${sep}rev=${rev}-patched`)
          return match.replace(url, bumped)
        })
      }), 'tailscale-surface: settings mirror persistence boot-URL bump')

      // Wrap the upstream bundleResource so the bundle body that ultimately
      // reaches the browser carries 'host' persistence regardless of which
      // upstream route (exact combo, source map, batched combo) delivered
      // it. Override is an own property on the service instance, so
      // this.bundleResource(...) inside serveBundle/fetchBundle resolves
      // to the wrapper instead of the prototype method.
      patchCtx.effect(() => {
        const cm = patchCtx.clientModules
        const orig = cm.bundleResource.bind(cm)
        cm.bundleResource = function (method, url) {
          const result = orig(method, url)
          if (result.status !== 200) return result
          const ct = result.headers?.['content-type'] ?? ''
          if (!ct.startsWith('text/javascript')) return result
          if (method === 'HEAD') return result
          const body = result.body
          const text = typeof body === 'string' ? body : (Buffer.isBuffer(body) ? body.toString('utf8') : Buffer.from(body).toString('utf8'))
          if (!PATCH_PATTERN.test(text)) {
            // Upstream no longer ships the buggy pattern — hand through
            // unchanged. The wrap cost is one extra Buffer allocation and
            // one regex test per request for this package; trivial.
            return result
          }
          const patched = text.replace(PATCH_PATTERN, PATCH_REPLACE)
          if (!patchObserved) {
            patchObserved = true
            console.log('tailscale-surface: settings mirror persistence patch active — Settings > Models over Tailscale will use host persistence')
          }
          const buf = Buffer.from(patched, 'utf8')
          return {
            ...result,
            body: buf,
            headers: {
              ...result.headers,
              'content-length': String(buf.length),
              // Override the upstream 1-year immutable cache so any browser
              // that fetched this URL before the patch started intercepting
              // revalidates on its next request.
              'cache-control': 'no-store',
            },
          }
        }
      }, 'tailscale-surface: settings mirror persistence bundleResource wrap')
    })
  }

  // Both routes read the `connection` service, so register them in one scope.
  //
  // /login — stable re-authentication URL, gated by a local passcode. dsh
  // web's launch token rotates on every restart and is otherwise only visible
  // in the daemon log, so a bookmarked device can't re-login after its 30-day
  // cookie lapses. This route verifies the passcode (scrypt hash stored in
  // ~/.dsh/profiles/tailscale-surface/auth.json, 0600) and only then
  // 302-redirects to /?token=<token>, reading the live launch token from the
  // `connection` service. The passcode adds a credential on top of Tailscale
  // identity (a compromised identity alone no longer reaches the daemon).
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
      const throttle = new Map() // ua -> { n, ts } for coarse brute-force damping
      const THRESHOLD = 5, WINDOW_MS = 60 * 1000
      const formPage = (err) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dsh login</title>
<style>
 body{display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0b0e14;color:#e6e9ef;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
 form{width:min(92vw,360px);padding:32px 28px;background:#151a24;border:1px solid #232a38;border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.45)}
 h1{margin:0 0 6px;font-size:17px;font-weight:600;letter-spacing:.2px}
 p{margin:0 0 18px;font-size:13px;color:#8b95a7}
 input{width:100%;box-sizing:border-box;padding:11px 12px;font-size:15px;border-radius:9px;border:1px solid #2c3547;background:#0f1420;color:#e6e9ef;outline:none}
 input:focus{border-color:#4f6b9e}
 button{margin-top:14px;width:100%;padding:11px;font-size:15px;font-weight:600;border:0;border-radius:9px;background:#3b82f6;color:#fff;cursor:pointer}
 .err{margin:0 0 14px;font-size:13px;color:#f87171}
</style></head>
<body><form method="post">
<h1>dsh</h1>
<p>Enter the login passcode for this Tailscale surface.</p>
${err ? '<p class="err">' + err + '</p>' : ''}
<input type="password" name="p" autocomplete="current-password" autofocus placeholder="Passcode">
<button type="submit">Sign in</button>
</form></body></html>`

      connCtx.effect(() => connCtx.webServer.register({
        kind: 'exact',
        path: config.loginPath,
        handler: async (req, res) => {
          // Enforce the same trusted-host fence the rest of the surface uses.
          // Only an untrusted Host (403) is rejected here; 401 (no cookie) is
          // fine — this IS the login endpoint. Blocks cross-origin CSRF from
          // driving a passcode login against a victim's session.
          let rejection
          try { rejection = conn.requestRejection({ headers: req.headers, method: req.method }) }
          catch (e) { rejection = void 0 }
          if (rejection === 403) { res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }); res.end(); return }
          if (req.method === 'GET' || req.method === 'HEAD') {
            res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
            res.end(formPage())
            return
          }
          if (req.method !== 'POST') { res.writeHead(405); res.end(); return }
          // coarse brute-force damping (per-User-Agent, in-memory, best effort)
          const ua = (req.headers['user-agent'] || 'unknown').slice(0, 200)
          const now = Date.now()
          const t = throttle.get(ua)
          if (t && now - t.ts < WINDOW_MS && t.n >= THRESHOLD) {
            res.writeHead(429, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '60' })
            res.end('tailscale-surface: too many attempts; retry in a minute')
            return
          }
          if (!t || now - t.ts >= WINDOW_MS) throttle.set(ua, { n: 0, ts: now })
          const entry = throttle.get(ua); entry.n += 1
          let raw = ''
          try {
            for await (const chunk of req) { raw += chunk; if (raw.length > 1300) break }
          } catch { /* fall through to failure */ }
          const submitted = new URLSearchParams(raw).get('p') || raw
          let auth
          try { auth = JSON.parse(await readFile(AUTH_FILE, 'utf8')) }
          catch { auth = null }
          const ok = (() => {
            try {
              if (!auth || auth.alg !== 'scrypt') return false
              const salt = Buffer.from(auth.salt, 'base64')
              const want = Buffer.from(auth.hash, 'base64')
              const got = crypto.scryptSync(String(submitted), salt, want.length, { N: auth.N, r: auth.r, p: auth.p })
              return got.length === want.length && crypto.timingSafeEqual(got, want)
            } catch { return false }
          })()
          if (!ok) {
            res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
            res.end(formPage('Incorrect passcode.'))
            return
          }
          throttle.delete(ua)
          let token
          try {
            token = new URL(conn.authenticatedUrl('http://127.0.0.1/')).searchParams.get('token')
          } catch (e) { token = null }
          if (typeof token !== 'string' || token.length === 0) {
            res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('tailscale-surface: connection service returned no launch token')
            return
          }
          res.writeHead(302, { 'location': '/?token=' + encodeURIComponent(token), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' })
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
