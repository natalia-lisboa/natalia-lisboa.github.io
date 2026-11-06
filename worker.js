/**
 * Nathalia Lisboa Advocacia — Cloudflare Edge Security & DataJud Proxy Worker
 * Plano: Cloudflare Workers Free (R$ 0,00/mês)
 * Recursos:
 *  1. OWASP Hardened Security Headers (CSP, HSTS, X-Frame-Options, nosniff, Permissions-Policy)
 *  2. Proxy Seguro DataJud CNJ (/api/datajud) com Cache de Borda (caches.default) e proteção SSRF
 *  3. Validação Server-Side Cloudflare Turnstile (/api/turnstile-verify) Anti-Bot / Anti-Brute-Force
 *  4. Servir Static Assets com isolamento e telemetria estruturada JSON
 */

const DEFAULT_DATAJUD_PUBLIC_KEY = 'cDZHYzlZa0JadVREZDJCendQbXY6SkJlTzNjLV9TRENyQk1RdnFKZGRQdw==';
const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA';

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com https://challenges.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https://zlnaushxdvuznlwmongk.supabase.co wss://zlnaushxdvuznlwmongk.supabase.co https://api-publica.datajud.cnj.jus.br https://challenges.cloudflare.com",
    "frame-src https://challenges.cloudflare.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ')
};

function applySecurityHeaders(response, requestId) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  headers.set('X-Request-Id', requestId);
  headers.set('X-Edge-Protection', 'Cloudflare-ZeroCost-Shield');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function jsonResponse(payload, status = 200, requestId = '') {
  const res = new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
  return applySecurityHeaders(res, requestId);
}

export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    // Log estruturado para Workers Observability
    console.log(JSON.stringify({
      level: 'info',
      requestId,
      method: request.method,
      path: url.pathname,
      clientIp
    }));

    // 1. Healthcheck & Security Status Endpoint
    if (url.pathname === '/api/health' && request.method === 'GET') {
      return jsonResponse({
        status: 'ok',
        edge: 'cloudflare-workers',
        security: 'owasp-hardened',
        requestId,
        timestamp: new Date().toISOString()
      }, 200, requestId);
    }

    // 2. Validação Server-Side do Cloudflare Turnstile (Anti-Bot / Anti-Força Bruta)
    if (url.pathname === '/api/turnstile-verify' && request.method === 'POST') {
      try {
        const body = await request.json();
        const token = String(body?.token || '').trim();
        if (!token) {
          return jsonResponse({ success: false, error: 'Token Turnstile ausente.' }, 400, requestId);
        }

        const secret = env.TURNSTILE_SECRET_KEY || TURNSTILE_TEST_SECRET;
        const formData = new FormData();
        formData.append('secret', secret);
        formData.append('response', token);
        formData.append('remoteip', clientIp);

        const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST',
          body: formData
        });
        const outcome = await verifyRes.json();
        return jsonResponse({
          success: Boolean(outcome.success),
          challenge_ts: outcome.challenge_ts || null,
          requestId
        }, outcome.success ? 200 : 403, requestId);
      } catch (err) {
        console.error(JSON.stringify({ level: 'error', requestId, route: '/api/turnstile-verify', message: err.message }));
        return jsonResponse({ success: false, error: 'Falha ao validar desafio Turnstile.' }, 500, requestId);
      }
    }

    // 3. Proxy Seguro DataJud CNJ com Cache na Borda (caches.default) e Proteção Anti-SSRF
    if (url.pathname === '/api/datajud' && request.method === 'POST') {
      try {
        const body = await request.json();
        const courtAlias = String(body?.court || '').toLowerCase().trim();
        const numeroProcesso = String(body?.numeroProcesso || '').replace(/\D/g, '');

        if (!/^[a-z0-9_]{2,15}$/.test(courtAlias)) {
          return jsonResponse({ error: 'Tribunal inválido.' }, 400, requestId);
        }
        if (numeroProcesso.length !== 20) {
          return jsonResponse({ error: 'Número CNJ deve conter 20 dígitos.' }, 400, requestId);
        }

        const cacheKeyUrl = new URL(request.url);
        cacheKeyUrl.pathname = `/__edge_cache/datajud/${courtAlias}/${numeroProcesso}`;
        const cacheKey = new Request(cacheKeyUrl.toString(), { method: 'GET' });
        const cache = caches.default;

        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
          return applySecurityHeaders(cachedResponse, requestId);
        }

        const apiKey = env.DATAJUD_API_KEY || DEFAULT_DATAJUD_PUBLIC_KEY;
        const targetUrl = `https://api-publica.datajud.cnj.jus.br/api_publica_${courtAlias}/_search`;

        const upstreamResponse = await fetch(targetUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `APIKey ${apiKey}`
          },
          body: JSON.stringify({
            query: {
              match: {
                numeroProcesso
              }
            }
          })
        });

        if (!upstreamResponse.ok) {
          return jsonResponse({
            error: `Tribunal respondeu HTTP ${upstreamResponse.status}`
          }, upstreamResponse.status, requestId);
        }

        const data = await upstreamResponse.json();
        const edgeCachedResponse = new Response(JSON.stringify(data), {
          status: 200,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'public, max-age=300'
          }
        });

        ctx.waitUntil(cache.put(cacheKey, edgeCachedResponse.clone()));
        return applySecurityHeaders(edgeCachedResponse, requestId);
      } catch (err) {
        console.error(JSON.stringify({ level: 'error', requestId, route: '/api/datajud', message: err.message }));
        return jsonResponse({ error: 'Erro ao consultar DataJud via Cloudflare Edge.' }, 502, requestId);
      }
    }

    // 4. Bloquear acesso público a arquivos internos de desenvolvimento/configuração
    const blockedPrefixes = ['/sql/', '/scripts/', '/tests/', '/src/', '/docs/', '/.superpowers/', '/wrangler.jsonc', '/worker.js'];
    if (blockedPrefixes.some(prefix => url.pathname.startsWith(prefix))) {
      return jsonResponse({ error: 'Acesso negado pela política de segurança de borda.' }, 403, requestId);
    }

    // 5. Servir Static Assets da aplicação com Security Headers OWASP
    if (env.ASSETS) {
      const assetRes = await env.ASSETS.fetch(request);
      return applySecurityHeaders(assetRes, requestId);
    }

    return jsonResponse({ error: 'Recurso não encontrado.' }, 404, requestId);
  }
};
