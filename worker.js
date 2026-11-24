/**
 * Nathalia Lisboa Advocacia — Cloudflare Edge Security, DataJud & Realtime Sync Worker
 * Plano: Cloudflare Workers Free (R$ 0,00/mês)
 * Recursos:
 *  1. OWASP Hardened Security Headers (CSP, HSTS, X-Frame-Options, nosniff, Permissions-Policy)
 *  2. Token-Bucket Edge Rate Limiter com poda automática de entradas antigas
 *  3. Proxy Seguro DataJud CNJ (/api/datajud) e Sincronização Híbrida (/api/realtime-sync: DJEN + MNI 2.2.2 + DataJud)
 *  4. Validação Server-Side Cloudflare Turnstile (/api/turnstile-verify) Anti-Bot / Anti-Brute-Force
 *  5. Servir Static Assets com isolamento e telemetria estruturada JSON
 */

const DEFAULT_DATAJUD_PUBLIC_KEY = 'cDZHYzlZa0JadVREZDJCendQbXY6SkJlTzNjLV9TRENyQk1RdnFKZGRQdw==';
const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA';
const REALTIME_FETCH_TIMEOUT_MS = 6500;

const ALLOWED_MNI_ENDPOINTS = new Set([
  'https://eproc1g.tjrj.jus.br/eproc/ws/controlador_ws.php?srv=intercomunicacao2.2',
  'https://eproc2g.tjrj.jus.br/eproc/ws/controlador_ws.php?srv=intercomunicacao2.2',
  'https://tjrj.pje.jus.br/1g/intercomunicacao',
  'https://tjrj.pje.jus.br/2g/intercomunicacao',
  'https://eproc1g.tjmg.jus.br/eproc/ws/controlador_ws.php?srv=intercomunicacao2.2',
  'https://pje.tjmg.jus.br/pje/intercomunicacao',
  'https://pje.trt1.jus.br/primeirograu/intercomunicacao',
  'https://pje.trt1.jus.br/segundograu/intercomunicacao'
]);

const DEFAULT_MNI_BY_COURT = {
  tjrj: [
    'https://eproc1g.tjrj.jus.br/eproc/ws/controlador_ws.php?srv=intercomunicacao2.2',
    'https://tjrj.pje.jus.br/1g/intercomunicacao'
  ],
  tjmg: [
    'https://eproc1g.tjmg.jus.br/eproc/ws/controlador_ws.php?srv=intercomunicacao2.2',
    'https://pje.tjmg.jus.br/pje/intercomunicacao'
  ],
  trt1: [
    'https://pje.trt1.jus.br/primeirograu/intercomunicacao',
    'https://pje.trt1.jus.br/segundograu/intercomunicacao'
  ]
};

const ALLOWED_ORIGINS = new Set([
  'https://natalia-lisboa.github.io',
  'https://minhaempresacrm.github.io'
]);

const DEV_LOCAL_ORIGINS = new Set([
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://localhost:8787',
  'http://127.0.0.1:8787'
]);

function validateAllowedOrigin(request, url, env = {}) {
  const origin = String(request.headers.get('Origin') || '').trim();
  const isProd = String(env?.ENVIRONMENT || 'production').toLowerCase() === 'production';
  const extraOrigins = String(env?.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  const allowSet = new Set([
    ...ALLOWED_ORIGINS,
    url.origin,
    ...extraOrigins,
    ...(isProd ? [] : DEV_LOCAL_ORIGINS)
  ]);

  // Se Origin estiver presente, exige correspondência exata na allowlist (bloqueia CSRF/abuso de terceiros)
  if (origin) {
    return allowSet.has(origin)
      ? { allowed: true, origin }
      : { allowed: false, origin: null };
  }

  // Sem header Origin: aceita apenas navegação/fetch comprovadamente same-origin ou Referer de origem permitida
  const fetchSite = String(request.headers.get('Sec-Fetch-Site') || '').toLowerCase();
  if (fetchSite === 'same-origin') {
    return { allowed: true, origin: url.origin };
  }

  const referer = String(request.headers.get('Referer') || '').trim();
  if (referer) {
    try {
      const refOrigin = new URL(referer).origin;
      if (allowSet.has(refOrigin)) {
        return { allowed: true, origin: refOrigin };
      }
    } catch (_) {}
  }

  return { allowed: false, origin: null };
}

function buildCorsHeaders(allowedOrigin) {
  if (!allowedOrigin) return {};
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-legal-token',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin'
  };
}

const DJEN_ENDPOINT = 'https://comunicaapi.pje.jus.br/api/v1/comunicacao';
const DATAJUD_ORIGIN = 'https://api-publica.datajud.cnj.jus.br';

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
    "connect-src 'self' https://zlnaushxdvuznlwmongk.supabase.co wss://zlnaushxdvuznlwmongk.supabase.co https://api-publica.datajud.cnj.jus.br https://comunicaapi.pje.jus.br https://challenges.cloudflare.com",
    "frame-src https://challenges.cloudflare.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ')
};

// Token-Bucket Edge Rate Limiter em memória com poda automática
const EDGE_RATE_BUCKETS = new Map();
let lastBucketPruneAt = 0;

function checkEdgeRateLimit(ip, limit = 24, windowMs = 60000) {
  const now = Date.now();
  const key = String(ip || '0.0.0.0');
  const refillPerMs = limit / windowMs;

  if (now - lastBucketPruneAt > windowMs || EDGE_RATE_BUCKETS.size > 1024) {
    lastBucketPruneAt = now;
    const expiry = windowMs * 2;
    for (const [k, entry] of EDGE_RATE_BUCKETS.entries()) {
      if (now - entry.lastSeen > expiry) {
        EDGE_RATE_BUCKETS.delete(k);
      }
    }
  }

  let bucket = EDGE_RATE_BUCKETS.get(key);
  if (!bucket) {
    bucket = { tokens: limit, lastRefill: now, lastSeen: now };
  } else {
    const elapsed = Math.max(0, now - bucket.lastRefill);
    bucket.tokens = Math.min(limit, bucket.tokens + elapsed * refillPerMs);
    bucket.lastRefill = now;
    bucket.lastSeen = now;
  }

  if (bucket.tokens < 1) {
    EDGE_RATE_BUCKETS.set(key, bucket);
    const retryAfterSec = Math.max(1, Math.ceil((1 - bucket.tokens) / refillPerMs / 1000));
    return { allowed: false, remaining: 0, retryAfterSec };
  }

  bucket.tokens -= 1;
  EDGE_RATE_BUCKETS.set(key, bucket);
  return { allowed: true, remaining: Math.floor(bucket.tokens), retryAfterSec: 0 };
}

function applySecurityHeaders(response, requestId, extraHeaders = {}) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(key, value);
  }
  for (const [key, value] of Object.entries(extraHeaders)) {
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

function jsonResponse(payload, status = 200, requestId = '', extraHeaders = {}) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  for (const [k, v] of Object.entries(extraHeaders)) {
    headers.set(k, v);
  }
  const res = new Response(JSON.stringify(payload), { status, headers });
  return applySecurityHeaders(res, requestId);
}

function escapeXml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function decodeXmlEntities(str) {
  return String(str || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function formatMniTimestamp(raw) {
  const s = String(raw || '').trim();
  if (/^\d{14}$/.test(s)) {
    return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}-03:00`;
  }
  if (/^\d{8}$/.test(s)) {
    return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T12:00:00-03:00`;
  }
  return s;
}

function unwrapMtomEnvelope(rawText) {
  const text = String(rawText || '');
  // Desembrulha multipart/related MTOM (--uuid:...) isolando o SOAP Envelope XML
  const envMatch = /<([a-zA-Z0-9_-]+:)?Envelope\b[\s\S]*?<\/([a-zA-Z0-9_-]+:)?Envelope>/i.exec(text);
  if (envMatch) {
    return envMatch[0].replace(/<(?:[a-zA-Z0-9_-]+:)?Include\b[^>]*\/>/gi, '');
  }
  if (text.includes('--uuid:')) {
    const parts = text.split(/--uuid:[^\r\n]+/);
    for (const part of parts) {
      const idx = part.indexOf('<');
      if (idx !== -1 && /Envelope/i.test(part)) {
        return part.slice(idx).trim();
      }
    }
  }
  return text;
}

function extractXmlTagText(xmlFragment, tagName) {
  const rx = new RegExp(`<(?:[a-zA-Z0-9_-]+:)?${tagName}\\b[^>]*>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_-]+:)?${tagName}>`, 'i');
  const m = rx.exec(xmlFragment);
  return m ? decodeXmlEntities(m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()) : '';
}

function parseMniMovementsXml(rawBody) {
  const xml = unwrapMtomEnvelope(rawBody);
  const movements = [];
  const movRegex = /<(?:[a-zA-Z0-9_-]+:)?movimento\b([^>]*)>([\s\S]*?)<\/(?:[a-zA-Z0-9_-]+:)?movimento>/gi;
  let match;
  while ((match = movRegex.exec(xml)) !== null) {
    const attrs = match[1] || '';
    const inner = match[2] || '';

    const attrDataHora = /\bdataHora\s*=\s*["']([^"']+)["']/i.exec(attrs);
    const attrId = /\bidentificadorMovimento\s*=\s*["']([^"']+)["']/i.exec(attrs);
    const rawDataHora = (attrDataHora && attrDataHora[1]) || extractXmlTagText(inner, 'dataHora');

    const natMatch = /<(?:[a-zA-Z0-9_-]+:)?movimentoNacional\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[a-zA-Z0-9_-]+:)?movimentoNacional>)/i.exec(inner);
    let codigoNacional = '';
    let nomeNacional = '';
    if (natMatch) {
      const natAttrs = natMatch[1] || '';
      const natInner = natMatch[2] || '';
      const codAttr = /\bcodigoNacional\s*=\s*["']([^"']+)["']/i.exec(natAttrs);
      codigoNacional = (codAttr && codAttr[1]) || extractXmlTagText(natInner, 'codigoNacional');
      nomeNacional = extractXmlTagText(natInner, 'descricao') || extractXmlTagText(natInner, 'nome');
    }

    const locMatch = /<(?:[a-zA-Z0-9_-]+:)?movimentoLocal\b([^>]*?)(?:\/>|>([\s\S]*?)<\/(?:[a-zA-Z0-9_-]+:)?movimentoLocal>)/i.exec(inner);
    let codigoLocal = '';
    let descLocal = '';
    if (locMatch) {
      const locAttrs = locMatch[1] || '';
      const locInner = locMatch[2] || '';
      const codLocAttr = /\bcodigoMovimento\s*=\s*["']([^"']+)["']/i.exec(locAttrs);
      codigoLocal = (codLocAttr && codLocAttr[1]) || extractXmlTagText(locInner, 'codigoMovimento');
      descLocal = extractXmlTagText(locInner, 'descricao') || extractXmlTagText(locInner, 'nome');
    }

    const complemento = extractXmlTagText(inner, 'complemento');
    const dataHoraIso = formatMniTimestamp(rawDataHora);

    movements.push({
      identificadorMovimento: (attrId && attrId[1]) || extractXmlTagText(inner, 'identificadorMovimento') || null,
      dataHora: dataHoraIso,
      dataHoraRaw: rawDataHora,
      codigoNacional: codigoNacional ? Number(codigoNacional) || codigoNacional : null,
      nomeMovimento: nomeNacional || descLocal || 'Movimentação MNI',
      codigoLocal: codigoLocal || null,
      complemento: complemento || ''
    });
  }
  return movements;
}

function resolveAllowedMniEndpoints(courtAlias, requestedEndpoint, numeroProcesso) {
  if (requestedEndpoint) {
    const clean = String(requestedEndpoint).trim();
    if (!ALLOWED_MNI_ENDPOINTS.has(clean)) {
      return { error: 'Endpoint MNI fora da allowlist de segurança Anti-SSRF.', endpoints: [] };
    }
    return { error: null, endpoints: [clean] };
  }
  const defaults = DEFAULT_MNI_BY_COURT[courtAlias] || [];
  if (defaults.length === 0) return { error: null, endpoints: [] };
  if (numeroProcesso.startsWith('30')) {
    return { error: null, endpoints: [defaults[0]] };
  }
  return { error: null, endpoints: defaults };
}

async function fetchWithTimeout(targetUrl, init, timeoutMs = REALTIME_FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(targetUrl, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryMniEndpoint(endpointUrl, idConsultante, senhaConsultante, numeroProcesso) {
  if (!ALLOWED_MNI_ENDPOINTS.has(endpointUrl)) {
    throw new Error('Endpoint MNI bloqueado pela política Anti-SSRF.');
  }
  const soapEnvelope = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://www.cnj.jus.br/servico-intercomunicacao-2.2.2/" xmlns:tip="http://www.cnj.jus.br/tipos-servico-intercomunicacao-2.2.2">',
    '  <soapenv:Header/>',
    '  <soapenv:Body>',
    '    <ser:consultarProcesso>',
    `      <tip:idConsultante>${escapeXml(idConsultante)}</tip:idConsultante>`,
    `      <tip:senhaConsultante>${escapeXml(senhaConsultante)}</tip:senhaConsultante>`,
    `      <tip:numeroProcesso>${escapeXml(numeroProcesso)}</tip:numeroProcesso>`,
    '      <tip:movimentos>true</tip:movimentos>',
    '      <tip:incluirCabecalho>true</tip:incluirCabecalho>',
    '      <tip:incluirDocumentos>false</tip:incluirDocumentos>',
    '    </ser:consultarProcesso>',
    '  </soapenv:Body>',
    '</soapenv:Envelope>'
  ].join('\n');

  const res = await fetchWithTimeout(endpointUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      'SOAPAction': '"http://www.cnj.jus.br/servico-intercomunicacao-2.2.2/consultarProcesso"'
    },
    body: soapEnvelope
  });

  if (!res.ok) {
    throw new Error(`MNI HTTP ${res.status}`);
  }
  const rawBody = await res.text();
  return parseMniMovementsXml(rawBody);
}

export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';

    // Log estruturado para Workers Observability (nunca registra segredos/senhas)
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
        realtimeSync: true,
        requestId,
        timestamp: new Date().toISOString()
      }, 200, requestId);
    }

    // 2. Validação Server-Side do Cloudflare Turnstile (Anti-Bot / Anti-Força Bruta)
    if (url.pathname === '/api/turnstile-verify' && request.method === 'POST') {
      const rate = checkEdgeRateLimit(`turnstile:${clientIp}`, 24, 60000);
      if (!rate.allowed) {
        return jsonResponse({ success: false, error: 'Limite de requisições excedido.' }, 429, requestId, {
          'Retry-After': String(rate.retryAfterSec)
        });
      }
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

        const verifyRes = await fetchWithTimeout('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
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

    // Preflight CORS estrito apenas para origens autorizadas em /api/datajud e /api/realtime-sync
    if ((url.pathname === '/api/datajud' || url.pathname === '/api/realtime-sync') && request.method === 'OPTIONS') {
      const originCheck = validateAllowedOrigin(request, url, env);
      if (!originCheck.allowed) {
        return jsonResponse({ error: 'Origin não permitida pela política Zero-Trust.' }, 403, requestId);
      }
      return applySecurityHeaders(
        new Response(null, { status: 204 }),
        requestId,
        buildCorsHeaders(originCheck.origin)
      );
    }

    // 3. Proxy Seguro DataJud CNJ com Cache na Borda (caches.default) e Proteção Anti-SSRF + Validação de Origin
    if (url.pathname === '/api/datajud' && request.method === 'POST') {
      const originCheck = validateAllowedOrigin(request, url, env);
      if (!originCheck.allowed) {
        return jsonResponse({ error: 'Origin não permitida para uso do proxy judicial.' }, 403, requestId);
      }
      const corsHeaders = buildCorsHeaders(originCheck.origin);

      const rate = checkEdgeRateLimit(`datajud:${clientIp}`, 24, 60000);
      if (!rate.allowed) {
        return jsonResponse({ error: 'Limite de requisições excedido na borda.' }, 429, requestId, {
          ...corsHeaders,
          'Retry-After': String(rate.retryAfterSec)
        });
      }
      try {
        const body = await request.json();
        const courtAlias = String(body?.court || '').toLowerCase().trim();
        const numeroProcesso = String(body?.numeroProcesso || '').replace(/\D/g, '');

        if (!/^[a-z0-9_]{2,15}$/.test(courtAlias)) {
          return jsonResponse({ error: 'Tribunal inválido.' }, 400, requestId, corsHeaders);
        }
        if (numeroProcesso.length !== 20) {
          return jsonResponse({ error: 'Número CNJ deve conter 20 dígitos.' }, 400, requestId, corsHeaders);
        }

        const cacheKeyUrl = new URL(request.url);
        cacheKeyUrl.pathname = `/__edge_cache/datajud/${courtAlias}/${numeroProcesso}`;
        const cacheKey = new Request(cacheKeyUrl.toString(), { method: 'GET' });
        const cache = caches.default;

        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
          return applySecurityHeaders(cachedResponse, requestId, corsHeaders);
        }

        const apiKey = env.DATAJUD_API_KEY || DEFAULT_DATAJUD_PUBLIC_KEY;
        const targetUrl = `${DATAJUD_ORIGIN}/api_publica_${courtAlias}/_search`;

        const upstreamResponse = await fetchWithTimeout(targetUrl, {
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
          }, upstreamResponse.status, requestId, corsHeaders);
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
        return applySecurityHeaders(edgeCachedResponse, requestId, corsHeaders);
      } catch (err) {
        console.error(JSON.stringify({ level: 'error', requestId, route: '/api/datajud', message: err.message }));
        return jsonResponse({ error: 'Erro ao consultar DataJud via Cloudflare Edge.' }, 502, requestId, corsHeaders);
      }
    }

    // 4. Sincronização Híbrida em Tempo Real (DJEN + MNI 2.2.2 SOAP/MTOM + DataJud) + Validação de Origin
    if (url.pathname === '/api/realtime-sync' && request.method === 'POST') {
      const originCheck = validateAllowedOrigin(request, url, env);
      if (!originCheck.allowed) {
        return jsonResponse({ ok: false, error: 'Origin não permitida para sincronização em tempo real.' }, 403, requestId);
      }
      const corsHeaders = buildCorsHeaders(originCheck.origin);

      const rate = checkEdgeRateLimit(`realtime:${clientIp}`, 24, 60000);
      if (!rate.allowed) {
        return jsonResponse({ ok: false, error: 'Limite de requisições excedido. Aguarde antes de sincronizar novamente.' }, 429, requestId, {
          ...corsHeaders,
          'Retry-After': String(rate.retryAfterSec)
        });
      }

      try {
        const body = await request.json();
        const courtAlias = String(body?.court || '').toLowerCase().trim();
        const numeroProcesso = String(body?.numeroProcesso || '').replace(/\D/g, '');
        const force = body?.force === true;
        const mniIdConsultante = String(body?.mniIdConsultante || '').trim();
        const mniSenha = String(body?.mniSenha || '').trim();
        const hasMniCredentials = Boolean(mniIdConsultante && mniSenha);

        if (!/^[a-z0-9_]{2,15}$/.test(courtAlias)) {
          return jsonResponse({ ok: false, error: 'Tribunal inválido.' }, 400, requestId, corsHeaders);
        }
        if (numeroProcesso.length !== 20) {
          return jsonResponse({ ok: false, error: 'Número CNJ deve conter 20 dígitos.' }, 400, requestId, corsHeaders);
        }

        const mniResolved = resolveAllowedMniEndpoints(courtAlias, body?.mniEndpoint, numeroProcesso);
        if (mniResolved.error) {
          return jsonResponse({ ok: false, error: mniResolved.error }, 403, requestId, corsHeaders);
        }

        // Cache de borda (TTL 45s) apenas quando force !== true e sem credencial MNI
        const cache = caches.default;
        let cacheKey = null;
        if (!force && !hasMniCredentials) {
          const cacheKeyUrl = new URL(request.url);
          cacheKeyUrl.pathname = `/__edge_cache/realtime-sync/${courtAlias}/${numeroProcesso}`;
          cacheKey = new Request(cacheKeyUrl.toString(), { method: 'GET' });
          const cachedResponse = await cache.match(cacheKey);
          if (cachedResponse) {
            return applySecurityHeaders(cachedResponse, requestId, corsHeaders);
          }
        }

        const djenUrl = `${DJEN_ENDPOINT}?numeroProcesso=${numeroProcesso}&itensPorPagina=100&pagina=1`;
        const datajudUrl = `${DATAJUD_ORIGIN}/api_publica_${courtAlias}/_search`;
        const apiKey = env.DATAJUD_API_KEY || DEFAULT_DATAJUD_PUBLIC_KEY;

        const djenPromise = (async () => {
          const r = await fetchWithTimeout(djenUrl, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
          });
          if (!r.ok) return [];
          const j = await r.json();
          return Array.isArray(j?.items) ? j.items : [];
        })();

        const datajudPromise = (async () => {
          const r = await fetchWithTimeout(datajudUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `APIKey ${apiKey}`
            },
            body: JSON.stringify({
              query: {
                match: { numeroProcesso }
              }
            })
          });
          if (!r.ok) return [];
          const j = await r.json();
          return Array.isArray(j?.hits?.hits) ? j.hits.hits : [];
        })();

        const mniPromise = hasMniCredentials && mniResolved.endpoints.length > 0
          ? (async () => {
              const epResults = await Promise.allSettled(
                mniResolved.endpoints.map(ep => queryMniEndpoint(ep, mniIdConsultante, mniSenha, numeroProcesso))
              );
              const allMovs = [];
              for (const r of epResults) {
                if (r.status === 'fulfilled' && Array.isArray(r.value) && r.value.length > 0) {
                  allMovs.push(...r.value);
                }
              }
              return allMovs;
            })()
          : Promise.resolve([]);

        const [djenRes, mniRes, djRes] = await Promise.allSettled([
          djenPromise,
          mniPromise,
          datajudPromise
        ]);

        const payload = {
          ok: true,
          djenItems: djenRes.status === 'fulfilled' ? djenRes.value : [],
          mniMovements: mniRes.status === 'fulfilled' ? mniRes.value : [],
          datajudHits: djRes.status === 'fulfilled' ? djRes.value : [],
          syncedAt: new Date().toISOString(),
          requestId
        };

        if (cacheKey) {
          const edgeCachedResponse = new Response(JSON.stringify(payload), {
            status: 200,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'public, max-age=45'
            }
          });
          ctx.waitUntil(cache.put(cacheKey, edgeCachedResponse.clone()));
          return applySecurityHeaders(edgeCachedResponse, requestId, corsHeaders);
        }

        return jsonResponse(payload, 200, requestId, corsHeaders);
      } catch (err) {
        console.error(JSON.stringify({ level: 'error', requestId, route: '/api/realtime-sync', message: err.message }));
        return jsonResponse({ ok: false, error: 'Erro ao executar sincronização híbrida na borda.' }, 502, requestId, corsHeaders);
      }
    }

    // 5. Bloquear acesso público a arquivos internos de desenvolvimento/configuração
    const blockedPrefixes = ['/sql/', '/scripts/', '/tests/', '/src/', '/docs/', '/backups/', '/.superpowers/', '/.env', '/wrangler.jsonc', '/worker.js'];
    if (blockedPrefixes.some(prefix => url.pathname.startsWith(prefix))) {
      return jsonResponse({ error: 'Acesso negado pela política de segurança de borda.' }, 403, requestId);
    }

    // 6. Servir Static Assets da aplicação com Security Headers OWASP
    if (env.ASSETS) {
      const assetRes = await env.ASSETS.fetch(request);
      return applySecurityHeaders(assetRes, requestId);
    }

    return jsonResponse({ error: 'Recurso não encontrado.' }, 404, requestId);
  }
};
