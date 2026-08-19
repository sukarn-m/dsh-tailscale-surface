// dsh-tailscale-surface — a Cordis plugin for the DeepSeek Harness web
// profile that makes a `tailscale serve` surface a first-class fact of the
// daemon.
//
// What it does:
//  - discovers the `tailscale serve` rule fronting this daemon and exports the
//    canonical external URL (DSH_TS_URL shell variable, system-prompt section,
//    /__ts/status route);
//  - relays the 15 privileged /api methods for VERIFIED operator logins
//    (tailscale serve injects Tailscale-User-Login and overwrites any
//    client-supplied value — verified empirically), dispatching in-process via
//    the apiProxy service. Direct local connections (no proxy headers) keep
//    the stock loopback behavior. This also closes, for these methods, the
//    Host-spoofing path that exists behind any Host-preserving proxy;
//  - exposePath(): register auxiliary surfaces on the main origin instead of
//    binding unreachable new ports.
import z from '@deepseek-ai/schemastery'

export const name = 'tailscale-surface'

export const Config = z.object({
  operatorLogins: z.array(String).default([]),
  servePort: z.natural().max(65535).default(8443),
  surfaceContext: z.boolean().default(true),
})

export const inject = ['subprocess', 'timer', 'webServer', 'apiProxy']

// [wire method, apiProxy namespace, function]
const RELAY_METHODS = [
  ['settings.describe', 'settings', 'describe'],
  ['settings.openDocument', 'settings', 'openDocument'],
  ['settings.update', 'settings', 'update'],
  ['settings.replace', 'settings', 'replace'],
  ['settings.mutate', 'settings', 'mutate'],
  ['credentials.describe', 'credentials', 'describe'],
  ['credentials.set', 'credentials', 'set'],
  ['credentials.unset', 'credentials', 'unset'],
  ['agentPreset.read', 'agentPresets', 'read'],
  ['agentPreset.copy', 'agentPresets', 'copy'],
  ['agentPreset.openDocument', 'agentPresets', 'openDocument'],
  ['agentPreset.remove', 'agentPresets', 'remove'],
  ['host.pickDirectory', 'host', 'pickDirectory'],
  ['host.openPath', 'host', 'openPath'],
  ['llm.discoverModels', 'llm', 'discoverModels'],
]

export function apply(ctx, config) {
  const state = {
    fqdn: null, tailnetIP: null, certOK: false, backendPort: null,
    serveHostPort: null, rulePresent: null, serveManageable: null,
    externalUrl: null, lastError: null, checkedAt: null,
  }
  const relay = {
    active: true, operatorLogins: config.operatorLogins.length,
    methods: 0, relayed: 0, rejected: 0, local: 0, errors: 0,
  }
  const exposed = []

  async function cli(args, timeoutMs) {
    const exe = await ctx.subprocess.resolveExecutable(args[0])
    const handle = ctx.subprocess.spawn({
      argv: [exe].concat(args.slice(1)),
      cwd: '/',
      stdio: { stdin: 'ignore', stdout: { maxBytes: 1048576 }, stderr: { maxBytes: 65536 } },
      graceMs: 2000,
    })
    const cancelWatchdog = ctx.timeout(() => handle.terminate(), timeoutMs)
    try {
      const outcome = await handle.done
      return {
        code: outcome.exitCode,
        out: handle.collected.stdout === undefined ? '' : handle.collected.stdout.readFrom(0).text,
        err: handle.collected.stderr === undefined ? '' : handle.collected.stderr.readFrom(0).text,
      }
    } finally {
      cancelWatchdog()
    }
  }

  function snapshot() {
    return {
      externalUrl: state.externalUrl, fqdn: state.fqdn, tailnetIP: state.tailnetIP,
      certOK: state.certOK, backendPort: state.backendPort, serveHostPort: state.serveHostPort,
      rulePresent: state.rulePresent, serveManageable: state.serveManageable,
      privilegedRelay: relay, exposedPaths: exposed.slice(),
      lastError: state.lastError, checkedAt: state.checkedAt,
    }
  }

  async function health() {
    try {
      const st = await cli(['tailscale', 'status', '--json'], 10000)
      if (st.code !== 0) throw new Error('tailscale status failed: ' + st.err.trim())
      const d = JSON.parse(st.out)
      const self = d.Self || {}
      state.fqdn = String(self.DNSName || '').replace(/\.$/, '')
      state.tailnetIP = (self.TailscaleIPs || [])[0] || null
      state.certOK = (d.CertDomains || []).indexOf(state.fqdn) !== -1
      if (state.fqdn === '') throw new Error('no tailscale identity (Self.DNSName empty)')
      state.backendPort = ctx.webServer.port
      const sv = await cli(['tailscale', 'serve', 'status', '--json'], 10000)
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
        const port = snap.backendPort === null ? config.servePortFallback || 3080 : snap.backendPort
        return cli(['tailscale', 'serve', '--bg', '--https=' + String(config.servePort), 'http://127.0.0.1:' + String(port)], 15000).then((r) => {
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

  // ── identity-gated privileged relay ─────────────────────────────────────
  const hget = (req, name) => {
    const v = req.headers[name]
    return typeof v === 'string' ? v : undefined
  }
  const sendJson = (res, status, obj) => {
    const body = JSON.stringify(obj)
    res.writeHead(status, {
      'content-type': 'application/json',
      'content-length': String(new TextEncoder().encode(body).length),
    })
    res.end(body)
  }
  const badRequest = (res, rpcId, message) => sendJson(res, 200, {
    type: 'server-response',
    rpcId: typeof rpcId === 'string' ? rpcId : 'invalid-request',
    result: { ok: false, error: { code: 'bad-request', message, details: { issues: [] } } },
  })
  const readBody = (req, capBytes) => new Promise((resolve, reject) => {
    const decoder = new TextDecoder()
    let text = ''
    let total = 0
    let settled = false
    const finish = (value) => { if (!settled) { settled = true; resolve(value) } }
    req.on('data', (chunk) => {
      if (settled) return
      total += chunk.length
      if (total > capBytes) { finish(null); return }
      text += decoder.decode(chunk, { stream: true })
    })
    req.on('end', () => { text += decoder.decode(); finish(text) })
    req.on('error', (e) => { if (!settled) { settled = true; reject(e) } })
  })

  for (const [method, ns, fn] of RELAY_METHODS) {
    ctx.effect(() => ctx.webServer.register({
      kind: 'exact',
      path: '/api/' + method,
      handler: async (req, res) => {
        if (req.method !== 'POST') { res.writeHead(405); res.end(); return }
        const served = hget(req, 'tailscale-headers-info') !== undefined
          || hget(req, 'tailscale-user-login') !== undefined
          || hget(req, 'x-forwarded-for') !== undefined
        if (served) {
          const login = hget(req, 'tailscale-user-login')
          if (login === undefined || config.operatorLogins.indexOf(login) === -1) {
            relay.rejected += 1
            res.writeHead(403)
            res.end('forbidden')
            return
          }
        } else {
          relay.local += 1
        }
        const raw = await readBody(req, 16777216)
        if (raw === null) { res.writeHead(413); res.end('payload too large'); return }
        let envelope = null
        try { envelope = JSON.parse(raw) } catch { envelope = null }
        if (envelope === null || typeof envelope !== 'object'
          || envelope.type !== 'client-request'
          || typeof envelope.rpcId !== 'string'
          || typeof envelope.method !== 'string'
          || !('payload' in envelope)) {
          badRequest(res, envelope && envelope.rpcId, 'invalid client-request message')
          return
        }
        if (envelope.method !== method) {
          badRequest(res, envelope.rpcId, 'method "' + envelope.method + '" does not match path "' + method + '"')
          return
        }
        const namespace = ctx.apiProxy[ns]
        const target = namespace === undefined ? undefined : namespace[fn]
        if (typeof target !== 'function') { res.writeHead(404); res.end('not found'); return }
        try {
          const narrow = await target.call(namespace, { rpcId: envelope.rpcId, payload: envelope.payload })
          relay.relayed += 1
          sendJson(res, 200, { type: 'server-response', rpcId: narrow.rpcId, result: narrow.result })
        } catch (e) {
          relay.errors += 1
          res.writeHead(500)
          res.end('handler failure: ' + String(e && e.message ? e.message : e))
        }
      },
    }), 'tailscale-surface: relay ' + method)
    relay.methods += 1
  }

  if (config.surfaceContext) {
    const shellEnv = ctx.get('shellEnv')
    if (shellEnv !== undefined) {
      ctx.effect(() => shellEnv.register({
        name: 'tailscale-surface',
        variables: {
          DSH_TS_URL: {
            description: "Canonical tailnet HTTPS URL of this DSH GUI (Tailscale serve surface). Prefer over DSH_WEB_URL for user-facing links: the user's browser cannot reach this host's loopback.",
          },
        },
        resolve: () => (state.externalUrl === null ? {} : { DSH_TS_URL: state.externalUrl }),
      }), 'tailscale-surface: shellEnv')
    }
    const systemPrompt = ctx.get('systemPrompt')
    if (systemPrompt !== undefined) {
      ctx.effect(() => systemPrompt.section({
        name: 'app:tailscale-surface',
        order: -97,
        text: () => {
          if (state.externalUrl === null) {
            return "Tailscale surface: not detected (yet). Until it is, treat every URL you would hand the user as suspect: their browser cannot resolve this host's 127.0.0.1 or LAN addresses. Check /__ts/status."
          }
          return 'The user reaches this GUI remotely through Tailscale at ' + state.externalUrl + ". Their browser CANNOT resolve this host's 127.0.0.1, localhost, or LAN addresses. Every user-facing URL you emit or a plugin mints MUST start with " + state.externalUrl + ' (also in env DSH_TS_URL) — never http://127.0.0.1:PORT, localhost, or LAN IPs. To add an auxiliary UI or endpoint, register a same-origin route via the tailscaleSurface service (exposePath) or the webServer service instead of binding a new port; a fresh port is unreachable to the user. Privileged RPCs (settings, credentials, model discovery, agent presets) are relayed for verified operator logins through this surface, so remote Settings works; a 403 on them means the caller\'s tailnet login is not allowlisted.'
        },
      }), 'tailscale-surface: prompt section')
    }
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

  refresh().then(
    (snap) => console.log('tailscale-surface: ' + (snap.externalUrl === null ? 'no serve rule found for this daemon' : snap.externalUrl) + ' (privileged relay active: ' + relay.methods + ' methods, ' + relay.operatorLogins + ' operator login(s))'),
    () => {},
  )
}
