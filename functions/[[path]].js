const UPSTREAM_DNS_PROVIDERS = [
  { url: 'https://jp-kix.doh.sb/dns-query', priority: 1, healthScore: 100, lastCheck: 0, consecutiveFailures: 0, fronting: 'jp-kix.doh.sb', avgResponseTime: 0, successCount: 0, totalRequests: 0, region: 'global', circuitState: 'closed', lastCircuitOpen: 0 },
];

const DNS_CACHE_TTL_MIN = 60;
const DNS_CACHE_TTL_MAX = 3600;
const DNS_CACHE_TTL_DEFAULT = 300;
const PARALLEL_RACING_COUNT = 10;
const RACE_TIMEOUT = 4000;
const FALLBACK_TIMEOUT = 3000;
const MAX_DNS_RESPONSE_SIZE = 4096;
const MAX_DNS_REQUEST_SIZE = 1024;
const HEALTH_CHECK_INTERVAL = 90000;
const ADAPTIVE_LEARNING_INTERVAL = 180000;
const RATE_LIMIT_REQUESTS = 200;
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_CLEANUP_INTERVAL = 120000;
const MAX_CONCURRENT_REQUESTS = 150;
const CIRCUIT_BREAKER_THRESHOLD = 5;
const CIRCUIT_BREAKER_TIMEOUT = 60000;
const NEGATIVE_CACHE_TTL = 300;
const DNS_PADDING_ENABLED = true;
const ECS_STRIPPING_ENABLED = true;

const dnsCache = new Map();
const negativeDnsCache = new Map();
const rateLimitMap = new Map();
const pendingRequests = new Map();
let lastCleanupTime = Date.now();
let lastHealthCheck = Date.now();
let lastAdaptiveLearning = Date.now();
let concurrentRequests = 0;
let globalRequestCount = 0;

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0'
];

const ACCEPT_HEADERS = [
  'application/dns-message',
  'application/dns-json',
  '*/*',
  'application/dns-message, application/dns-json',
  'application/dns-message;q=0.9, */*;q=0.8'
];

const ADDITIONAL_HEADERS = [
  { 'X-Request-ID': () => crypto.randomUUID() },
  { 'X-Client-Version': () => `DoH/${Math.floor(Math.random() * 10) + 1}.${Math.floor(Math.random() * 10)}` },
  { 'Accept-Language': () => ['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en;q=0.8'][Math.floor(Math.random() * 3)] },
  { 'Sec-CH-UA': () => `"Chromium";v="${120 + Math.floor(Math.random() * 10)}", "Google Chrome";v="${120 + Math.floor(Math.random() * 10)}"` }
];

function getRandomUserAgent() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function getRandomAcceptHeader() {
  return ACCEPT_HEADERS[Math.floor(Math.random() * ACCEPT_HEADERS.length)];
}

function getAdaptiveTimeout(provider) {
  const baseTimeout = RACE_TIMEOUT;
  if (provider.avgResponseTime > 0) {
    return Math.min(baseTimeout, Math.max(1000, provider.avgResponseTime * 3));
  }
  return baseTimeout;
}

function checkCircuitBreaker(provider) {
  const now = Date.now();
  if (provider.circuitState === 'open') {
    if (now - provider.lastCircuitOpen > CIRCUIT_BREAKER_TIMEOUT) {
      provider.circuitState = 'half-open';
      return true;
    }
    return false;
  }
  if (provider.consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
    provider.circuitState = 'open';
    provider.lastCircuitOpen = now;
    return false;
  }
  return true;
}

function getClientRegion(cfData) {
  if (!cfData || !cfData.country) return 'global';
  const country = cfData.country;
  if (['US', 'CA', 'MX'].includes(country)) return 'na';
  if (['CN', 'JP', 'KR', 'SG', 'TW', 'IN'].includes(country)) return 'asia';
  if (['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'CH', 'SE', 'NO', 'FI', 'PL', 'CZ'].includes(country)) return 'eu';
  if (['AU', 'NZ'].includes(country)) return 'oceania';
  if (['BR', 'AR', 'CL'].includes(country)) return 'sa';
  return 'global';
}

function calculateProviderScore(provider, clientRegion = 'global') {
  const now = Date.now();
  const timeSinceLastCheck = now - provider.lastCheck;
  const healthWeight = 0.35;
  const speedWeight = 0.30;
  const reliabilityWeight = 0.20;
  const regionWeight = 0.15;

  let healthScore = provider.healthScore;
  if (provider.consecutiveFailures > 0) {
    healthScore = Math.max(0, healthScore - (provider.consecutiveFailures * 12));
  }

  let speedScore = 100;
  if (provider.avgResponseTime > 0) {
    speedScore = Math.max(0, 100 - (provider.avgResponseTime / 40));
  }

  let reliabilityScore = 100;
  if (provider.totalRequests > 10) {
    const successRate = (provider.successCount / provider.totalRequests) * 100;
    reliabilityScore = successRate;
  }

  let regionScore = 50;
  if (provider.region === clientRegion) {
    regionScore = 100;
  } else if (provider.region === 'global') {
    regionScore = 75;
  }

  const freshnessPenalty = Math.min(15, timeSinceLastCheck / 12000);

  const totalScore = (healthScore * healthWeight) +
                    (speedScore * speedWeight) +
                    (reliabilityScore * reliabilityWeight) +
                    (regionScore * regionWeight) -
                    freshnessPenalty;

  return Math.max(0, Math.min(100, totalScore));
}

function selectBestProviders(count, clientRegion = 'global') {
  const healthyProviders = UPSTREAM_DNS_PROVIDERS.filter(p =>
    p.healthScore > 25 &&
    p.consecutiveFailures < CIRCUIT_BREAKER_THRESHOLD &&
    checkCircuitBreaker(p)
  );

  if (healthyProviders.length === 0) {
    UPSTREAM_DNS_PROVIDERS.forEach(p => {
      p.healthScore = 100;
      p.consecutiveFailures = 0;
      p.circuitState = 'closed';
    });
    return UPSTREAM_DNS_PROVIDERS.slice(0, count);
  }

  const scoredProviders = healthyProviders.map(provider => ({
    provider,
    score: calculateProviderScore(provider, clientRegion)
  }));

  scoredProviders.sort((a, b) => b.score - a.score);

  const diversityPool = scoredProviders.slice(0, Math.min(25, scoredProviders.length));
  const randomIndex = Math.floor(Math.random() * Math.min(8, diversityPool.length));
  if (randomIndex > 0 && diversityPool[randomIndex]) {
    [diversityPool[0], diversityPool[randomIndex]] = [diversityPool[randomIndex], diversityPool[0]];
  }

  return diversityPool.slice(0, count).map(item => item.provider);
}

function updateProviderMetrics(provider, success, responseTime) {
  provider.totalRequests++;
  provider.lastCheck = Date.now();

  if (success) {
    provider.successCount++;
    provider.consecutiveFailures = 0;
    provider.healthScore = Math.min(100, provider.healthScore + 6);
    if (provider.circuitState === 'half-open') {
      provider.circuitState = 'closed';
    }

    if (provider.avgResponseTime === 0) {
      provider.avgResponseTime = responseTime;
    } else {
      provider.avgResponseTime = (provider.avgResponseTime * 0.65) + (responseTime * 0.35);
    }
  } else {
    provider.consecutiveFailures++;
    provider.healthScore = Math.max(0, provider.healthScore - 12);
  }
}

async function performAdaptiveLearning() {
  const now = Date.now();
  if (now - lastAdaptiveLearning < ADAPTIVE_LEARNING_INTERVAL) {
    return;
  }
  lastAdaptiveLearning = now;

  UPSTREAM_DNS_PROVIDERS.forEach(provider => {
    if (provider.totalRequests > 30) {
      const successRate = (provider.successCount / provider.totalRequests) * 100;

      if (successRate < 40) {
        provider.healthScore = Math.max(15, provider.healthScore - 20);
      } else if (successRate > 97) {
        provider.healthScore = Math.min(100, provider.healthScore + 12);
      }

      if (provider.avgResponseTime > 2500) {
        provider.healthScore = Math.max(25, provider.healthScore - 12);
      } else if (provider.avgResponseTime < 400) {
        provider.healthScore = Math.min(100, provider.healthScore + 8);
      }
    }

    if (now - provider.lastCheck > 900000) {
      provider.healthScore = Math.max(40, provider.healthScore - 15);
    }
  });
}

async function performHealthCheck() {
  const now = Date.now();
  if (now - lastHealthCheck < HEALTH_CHECK_INTERVAL) {
    return;
  }
  lastHealthCheck = now;

  const testQuery = new Uint8Array([
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01
  ]);

  const providersToCheck = UPSTREAM_DNS_PROVIDERS
    .filter(p => now - p.lastCheck > HEALTH_CHECK_INTERVAL)
    .slice(0, 12);

  const healthCheckPromises = providersToCheck.map(async (provider) => {
    const startTime = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);

      const response = await fetch(provider.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
          'User-Agent': getRandomUserAgent()
        },
        body: testQuery,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;

      if (response.ok) {
        updateProviderMetrics(provider, true, responseTime);
      } else {
        updateProviderMetrics(provider, false, responseTime);
      }
    } catch (error) {
      const responseTime = Date.now() - startTime;
      updateProviderMetrics(provider, false, responseTime);
    }
  });

  await Promise.allSettled(healthCheckPromises);
}

function applyDnsPadding(dnsQuery) {
  if (!DNS_PADDING_ENABLED) return dnsQuery;
  try {
    const view = new Uint8Array(dnsQuery);
    if (view.length < 12) return dnsQuery;

    const arcount = (view[10] << 8) | view[11];
    if (arcount > 0) return dnsQuery;

    const paddingDataSize = Math.floor(Math.random() * 60) + 16;
    const rdlength = 4 + paddingDataSize;
    const optRRSize = 11 + rdlength;
    const optRR = new Uint8Array(optRRSize);

    let i = 0;
    optRR[i++] = 0x00;
    optRR[i++] = 0x00;
    optRR[i++] = 0x29;
    optRR[i++] = 0x10;
    optRR[i++] = 0x00;
    optRR[i++] = 0x00;
    optRR[i++] = 0x00;
    optRR[i++] = 0x00;
    optRR[i++] = 0x00;
    optRR[i++] = (rdlength >> 8) & 0xFF;
    optRR[i++] = rdlength & 0xFF;
    optRR[i++] = 0x00;
    optRR[i++] = 0x0C;
    optRR[i++] = (paddingDataSize >> 8) & 0xFF;
    optRR[i++] = paddingDataSize & 0xFF;

    const result = new Uint8Array(view.length + optRR.length);
    result.set(view);
    result.set(optRR, view.length);
    result[10] = 0x00;
    result[11] = 0x01;

    return result.buffer;
  } catch (e) {
    return dnsQuery;
  }
}

function stripECS(dnsQuery) {
  if (!ECS_STRIPPING_ENABLED) return dnsQuery;
  try {
    const view = new Uint8Array(dnsQuery);
    if (view.length < 12) return dnsQuery;

    const arcount = (view[10] << 8) | view[11];
    if (arcount === 0) return dnsQuery;

    let offset = 12;
    const qdcount = (view[4] << 8) | view[5];

    for (let i = 0; i < qdcount && offset < view.length; i++) {
      while (offset < view.length) {
        const len = view[offset];
        if (len === 0) { offset++; break; }
        if ((len & 0xC0) === 0xC0) { offset += 2; break; }
        offset += len + 1;
      }
      offset += 4;
    }

    const ancount = (view[6] << 8) | view[7];
    const nscount = (view[8] << 8) | view[9];
    const skipSections = ancount + nscount;

    for (let i = 0; i < skipSections && offset < view.length; i++) {
      while (offset < view.length) {
        const len = view[offset];
        if (len === 0) { offset++; break; }
        if ((len & 0xC0) === 0xC0) { offset += 2; break; }
        offset += len + 1;
      }
      if (offset + 10 > view.length) return dnsQuery;
      const rdlength = (view[offset + 8] << 8) | view[offset + 9];
      offset += 10 + rdlength;
    }

    let optStart = -1;
    let optEnd = -1;
    let scanOffset = offset;

    for (let i = 0; i < arcount && scanOffset < view.length; i++) {
      const rrStart = scanOffset;
      while (scanOffset < view.length) {
        const len = view[scanOffset];
        if (len === 0) { scanOffset++; break; }
        if ((len & 0xC0) === 0xC0) { scanOffset += 2; break; }
        scanOffset += len + 1;
      }
      if (scanOffset + 10 > view.length) break;
      const rrType = (view[scanOffset] << 8) | view[scanOffset + 1];
      const rdlength = (view[scanOffset + 8] << 8) | view[scanOffset + 9];
      const rrEnd = scanOffset + 10 + rdlength;
      if (rrType === 41) {
        optStart = rrStart;
        optEnd = rrEnd;
        break;
      }
      scanOffset = rrEnd;
    }

    if (optStart === -1) return dnsQuery;

    const optNameEnd = optStart + 1;
    const optRdataStart = optNameEnd + 9;
    const optRdataEnd = optEnd;

    let hasECS = false;
    let rPos = optRdataStart;
    while (rPos + 4 <= optRdataEnd) {
      const optCode = (view[rPos] << 8) | view[rPos + 1];
      const optLen = (view[rPos + 2] << 8) | view[rPos + 3];
      if (optCode === 8) { hasECS = true; break; }
      rPos += 4 + optLen;
    }

    if (!hasECS) return dnsQuery;

    const newRdataBytes = [];
    rPos = optRdataStart;
    while (rPos + 4 <= optRdataEnd) {
      const optCode = (view[rPos] << 8) | view[rPos + 1];
      const optLen = (view[rPos + 2] << 8) | view[rPos + 3];
      if (optCode !== 8) {
        for (let j = rPos; j < rPos + 4 + optLen && j < view.length; j++) {
          newRdataBytes.push(view[j]);
        }
      }
      rPos += 4 + optLen;
    }

    const newRdlength = newRdataBytes.length;
    const sizeDiff = (optRdataEnd - optRdataStart) - newRdlength;
    const resultSize = view.length - sizeDiff;
    const result = new Uint8Array(resultSize);

    let writePos = 0;
    for (let j = 0; j < optRdataStart; j++) result[writePos++] = view[j];

    result[optRdataStart - 2] = (newRdlength >> 8) & 0xFF;
    result[optRdataStart - 1] = newRdlength & 0xFF;

    for (const b of newRdataBytes) result[writePos++] = b;

    for (let j = optRdataEnd; j < view.length; j++) result[writePos++] = view[j];

    return result.buffer;
  } catch (e) {
    return dnsQuery;
  }
}

function buildEnhancedHeaders(baseHeaders) {
  const headers = { ...baseHeaders };

  if (Math.random() < 0.4) {
    const randomHeader = ADDITIONAL_HEADERS[Math.floor(Math.random() * ADDITIONAL_HEADERS.length)];
    const headerKey = Object.keys(randomHeader)[0];
    const headerValue = randomHeader[headerKey]();
    headers[headerKey] = headerValue;
  }

  if (Math.random() < 0.25) {
    headers['X-Forwarded-For'] = `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  }

  return headers;
}

async function raceMultipleProviders(dnsQuery, headers, clientRegion = 'global') {
  let processedQuery = applyDnsPadding(dnsQuery);
  processedQuery = stripECS(processedQuery);

  const selectedProviders = selectBestProviders(PARALLEL_RACING_COUNT, clientRegion);

  const racePromises = selectedProviders.map(async (provider) => {
    const startTime = Date.now();
    const controller = new AbortController();
    const adaptiveTimeout = getAdaptiveTimeout(provider);
    const timeoutId = setTimeout(() => controller.abort(), adaptiveTimeout);

    try {
      const requestHeaders = buildEnhancedHeaders({
        'Content-Type': 'application/dns-message',
        'Accept': getRandomAcceptHeader(),
        'User-Agent': getRandomUserAgent(),
        'Cache-Control': 'no-cache',
        'DNT': '1'
      });

      const response = await fetch(provider.url, {
        method: 'POST',
        headers: requestHeaders,
        body: processedQuery,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;

      if (!response.ok) {
        updateProviderMetrics(provider, false, responseTime);
        throw new Error(`HTTP ${response.status}`);
      }

      const responseData = await response.arrayBuffer();

      if (responseData.byteLength > MAX_DNS_RESPONSE_SIZE) {
        updateProviderMetrics(provider, false, responseTime);
        throw new Error('Response too large');
      }

      updateProviderMetrics(provider, true, responseTime);

      return {
        data: responseData,
        provider: provider.url,
        responseTime: responseTime
      };

    } catch (error) {
      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;
      updateProviderMetrics(provider, false, responseTime);
      throw error;
    }
  });

  return Promise.any(racePromises);
}

async function fallbackProviderRequest(dnsQuery, headers, excludeProviders = [], clientRegion = 'global') {
  const availableProviders = UPSTREAM_DNS_PROVIDERS
    .filter(p =>
      !excludeProviders.includes(p.url) &&
      p.healthScore > 15 &&
      checkCircuitBreaker(p)
    )
    .sort((a, b) => calculateProviderScore(b, clientRegion) - calculateProviderScore(a, clientRegion))
    .slice(0, 8);

  for (const provider of availableProviders) {
    const startTime = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FALLBACK_TIMEOUT);

    try {
      const requestHeaders = buildEnhancedHeaders({
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'User-Agent': getRandomUserAgent()
      });

      const response = await fetch(provider.url, {
        method: 'POST',
        headers: requestHeaders,
        body: dnsQuery,
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;

      if (response.ok) {
        const responseData = await response.arrayBuffer();
        updateProviderMetrics(provider, true, responseTime);
        return {
          data: responseData,
          provider: provider.url,
          responseTime: responseTime
        };
      }

      updateProviderMetrics(provider, false, responseTime);
    } catch (error) {
      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;
      updateProviderMetrics(provider, false, responseTime);
    }
  }

  throw new Error('All fallback providers failed');
}

function getCacheKey(dnsQuery) {
  const view = new Uint8Array(dnsQuery);
  let hash = 2166136261;
  for (let i = 4; i < view.length; i++) {
    hash ^= view[i];
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return `dns_${hash}`;
}

function getCachedResponse(cacheKey) {
  const cached = dnsCache.get(cacheKey);
  if (!cached) return null;

  if (Date.now() - cached.timestamp > cached.ttl * 1000) {
    dnsCache.delete(cacheKey);
    return null;
  }

  return cached.response;
}

function setCachedResponse(cacheKey, response, ttl = DNS_CACHE_TTL_DEFAULT) {
  const finalTTL = Math.max(DNS_CACHE_TTL_MIN, Math.min(DNS_CACHE_TTL_MAX, ttl));
  dnsCache.set(cacheKey, {
    response: response,
    timestamp: Date.now(),
    ttl: finalTTL
  });

  if (dnsCache.size > 8000) {
    const sortedEntries = Array.from(dnsCache.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toDelete = sortedEntries.slice(0, 2000);
    toDelete.forEach(([key]) => dnsCache.delete(key));
  }
}

function checkNegativeCache(cacheKey) {
  const cached = negativeDnsCache.get(cacheKey);
  if (!cached) return null;

  if (Date.now() - cached.timestamp > NEGATIVE_CACHE_TTL * 1000) {
    negativeDnsCache.delete(cacheKey);
    return null;
  }

  return cached.response;
}

function setNegativeCache(cacheKey, response) {
  negativeDnsCache.set(cacheKey, {
    response: response,
    timestamp: Date.now()
  });

  if (negativeDnsCache.size > 2000) {
    const oldestKeys = Array.from(negativeDnsCache.keys()).slice(0, 500);
    oldestKeys.forEach(key => negativeDnsCache.delete(key));
  }
}

function isNXDOMAIN(dnsResponse) {
  try {
    const view = new DataView(dnsResponse);
    const flags = view.getUint16(2);
    const rcode = flags & 0x000F;
    return rcode === 3;
  } catch (e) {
    return false;
  }
}

function extractTTL(dnsResponse) {
  try {
    const view = new DataView(dnsResponse);
    let offset = 12;
    const qdcount = view.getUint16(4);

    for (let i = 0; i < qdcount; i++) {
      while (offset < dnsResponse.byteLength && view.getUint8(offset) !== 0) {
        const len = view.getUint8(offset);
        if (len > 63) break;
        offset += len + 1;
      }
      offset += 5;
    }

    if (offset + 10 < dnsResponse.byteLength) {
      offset += 10;
      const ttl = view.getUint32(offset);
      return Math.min(ttl, DNS_CACHE_TTL_MAX);
    }
  } catch (e) {
    return DNS_CACHE_TTL_DEFAULT;
  }
  return DNS_CACHE_TTL_DEFAULT;
}

function isRateLimited(clientIP) {
  const now = Date.now();

  if (now - lastCleanupTime > RATE_LIMIT_CLEANUP_INTERVAL) {
    const cutoff = now - RATE_LIMIT_WINDOW;
    for (const [ip, data] of rateLimitMap.entries()) {
      if (data.windowStart < cutoff) {
        rateLimitMap.delete(ip);
      }
    }
    lastCleanupTime = now;
  }

  let clientData = rateLimitMap.get(clientIP);

  if (!clientData || now - clientData.windowStart > RATE_LIMIT_WINDOW) {
    clientData = {
      count: 0,
      windowStart: now
    };
    rateLimitMap.set(clientIP, clientData);
  }

  clientData.count++;

  return clientData.count > RATE_LIMIT_REQUESTS;
}

function buildCORSHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, Cache-Control, DNT',
    'Access-Control-Max-Age': '86400'
  };
}

async function handleDNSQuery(request) {
  const url = new URL(request.url);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cfData = request.cf || {};
  const clientRegion = getClientRegion(cfData);
  const origin = request.headers.get('Origin');
  const corsHeaders = buildCORSHeaders(origin);
  const acceptHeader = request.headers.get('Accept') || '';
  const wantsJSON = acceptHeader.includes('application/dns-json');

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (isRateLimited(clientIP)) {
    return new Response('Rate limit exceeded', {
      status: 429,
      headers: {
        ...corsHeaders,
        'Retry-After': '60',
        'Content-Type': 'text/plain',
        'X-Rate-Limit': `${RATE_LIMIT_REQUESTS}/${RATE_LIMIT_WINDOW/1000}s`
      }
    });
  }

  let dnsQuery;

  if (request.method === 'POST') {
    dnsQuery = await request.arrayBuffer();
  } else if (request.method === 'GET') {
    const dnsParam = url.searchParams.get('dns');
    if (!dnsParam) {
      if (wantsJSON) {
        const name = url.searchParams.get('name');
        const type = url.searchParams.get('type') || 'A';
        if (name) {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), RACE_TIMEOUT);
          try {
            const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
            const resp = await fetch(cfUrl, {
              headers: { 'Accept': 'application/dns-json', 'User-Agent': getRandomUserAgent() },
              signal: controller.signal
            });
            clearTimeout(timeoutId);
            if (resp.ok) {
              const jsonData = await resp.json();
              return new Response(JSON.stringify(jsonData), {
                status: 200,
                headers: { ...corsHeaders, 'Content-Type': 'application/dns-json', 'X-Cache': 'MISS' }
              });
            }
          } catch (e) {
            clearTimeout(timeoutId);
          }
          return new Response(JSON.stringify({ Status: 2 }), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/dns-json' }
          });
        }
      }
      return new Response('Missing dns parameter', { status: 400, headers: corsHeaders });
    }
    try {
      const paddedDns = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
      const padding = '='.repeat((4 - (paddedDns.length % 4)) % 4);
      dnsQuery = Uint8Array.from(atob(paddedDns + padding), c => c.charCodeAt(0)).buffer;
    } catch (e) {
      return new Response('Invalid dns parameter', { status: 400, headers: corsHeaders });
    }
  } else {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  if (dnsQuery.byteLength > MAX_DNS_REQUEST_SIZE) {
    return new Response('Request too large', { status: 413, headers: corsHeaders });
  }

  if (concurrentRequests >= MAX_CONCURRENT_REQUESTS) {
    return new Response('Server busy', { status: 503, headers: corsHeaders });
  }

  concurrentRequests++;
  globalRequestCount++;

  try {
    performHealthCheck().catch(() => {});
    performAdaptiveLearning().catch(() => {});

    const cacheKey = getCacheKey(dnsQuery);

    const negativeCached = checkNegativeCache(cacheKey);
    if (negativeCached) {
      return new Response(negativeCached, {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/dns-message',
          'Cache-Control': `public, max-age=${NEGATIVE_CACHE_TTL}`,
          'X-Cache': 'NEGATIVE-HIT',
          'X-Provider': 'negative-cache'
        }
      });
    }

    const cachedResponse = getCachedResponse(cacheKey);
    if (cachedResponse) {
      return new Response(cachedResponse, {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/dns-message',
          'Cache-Control': `public, max-age=${DNS_CACHE_TTL_DEFAULT}`,
          'X-Cache': 'HIT',
          'X-Provider': 'cache',
          'X-Client-Region': clientRegion
        }
      });
    }

    if (pendingRequests.has(cacheKey)) {
      try {
        const coalescedResult = await pendingRequests.get(cacheKey);
        return new Response(coalescedResult.data, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/dns-message',
            'Cache-Control': `public, max-age=${extractTTL(coalescedResult.data)}`,
            'X-Cache': 'COALESCED',
            'X-Provider': coalescedResult.provider,
            'X-Response-Time': `${coalescedResult.responseTime}ms`,
            'X-Client-Region': clientRegion
          }
        });
      } catch (e) {
      }
    }

    const requestPromise = raceMultipleProviders(dnsQuery, request.headers, clientRegion)
      .catch(() => fallbackProviderRequest(dnsQuery, request.headers, [], clientRegion));

    pendingRequests.set(cacheKey, requestPromise);

    let result;
    try {
      result = await requestPromise;
    } finally {
      pendingRequests.delete(cacheKey);
    }

    if (isNXDOMAIN(result.data)) {
      setNegativeCache(cacheKey, result.data);
    } else {
      const ttl = extractTTL(result.data);
      setCachedResponse(cacheKey, result.data, ttl);
    }

    return new Response(result.data, {
      status: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/dns-message',
        'Cache-Control': `public, max-age=${extractTTL(result.data)}`,
        'X-Cache': 'MISS',
        'X-Provider': result.provider,
        'X-Response-Time': `${result.responseTime}ms`,
        'X-Client-Region': clientRegion
      }
    });

  } catch (error) {
    return new Response('DNS query failed', {
      status: 502,
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/plain',
        'X-Error': error.message
      }
    });
  } finally {
    concurrentRequests--;
  }
}

function generateAppleProfile(requestUrl) {
  const baseUrl = new URL(requestUrl);
  const dohUrl = `${baseUrl.protocol}//${baseUrl.hostname}/dns-query`;
  const hostname = baseUrl.hostname;

  const uuid1 = crypto.randomUUID();
  const uuid2 = crypto.randomUUID();
  const uuid3 = crypto.randomUUID();

  const mobileconfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures device to use Anonymous DoH Proxy</string>
            <key>PayloadDisplayName</key>
            <string>Anonymous DoH Proxy</string>
            <key>PayloadIdentifier</key>
            <string>com.cloudflare.${uuid2}.dnsSettings.managed</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid3}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>This profile enables encrypted DNS (DNS over HTTPS) on iOS, iPadOS, and macOS devices using your personal DoH Proxy.
    
Engineered by: Anonymous</string>
    <key>PayloadDisplayName</key>
    <string>Anonymous DoH Proxy - ${hostname}</string>
    <key>PayloadIdentifier</key>
    <string>com.cloudflare.${uuid1}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid1}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
  return mobileconfig;
}

function generateStatsPage() {
  const totalProviders = UPSTREAM_DNS_PROVIDERS.length;
  const healthyProviders = UPSTREAM_DNS_PROVIDERS.filter(p => p.healthScore > 50).length;
  const avgHealth = UPSTREAM_DNS_PROVIDERS.reduce((sum, p) => sum + p.healthScore, 0) / totalProviders;

  const topProviders = UPSTREAM_DNS_PROVIDERS
    .filter(p => p.totalRequests > 0)
    .sort((a, b) => calculateProviderScore(b) - calculateProviderScore(a))
    .slice(0, 15);

  return `<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DoH Proxy Pro — آمار زنده</title>
    <style>
        :root {
            --canvas-default: #0d1117;
            --canvas-subtle: #161b22;
            --canvas-inset: #010409;
            --canvas-overlay: #1c2128;
            --border-default: #30363d;
            --fg-default: #e6edf3;
            --fg-muted: #8b949e;
            --accent-fg: #4493f8;
            --accent-emphasis: #1f6feb;
            --success-fg: #3fb950;
            --success-emphasis: #238636;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, "SF Mono", "Segoe UI Mono", "Roboto Mono", Menlo, Consolas, monospace;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--font-sans);
            background-color: var(--canvas-default);
            color: var(--fg-default);
            min-height: 100vh;
        }
        .topbar {
            background: rgba(13, 17, 23, 0.85);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-default);
            padding: 12px 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .topbar a {
            color: var(--fg-default);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.95em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 24px 40px;
        }
        h1 {
            color: var(--fg-default);
            font-size: 2em;
            margin-bottom: 6px;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .subtitle {
            color: var(--fg-muted);
            margin-bottom: 32px;
            font-size: 1em;
            direction: ltr;
            text-align: right;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 14px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            padding: 20px;
            border-radius: 10px;
            transition: border-color 0.15s, transform 0.15s;
        }
        .stat-card:hover {
            border-color: var(--accent-fg);
            transform: translateY(-2px);
        }
        .stat-label {
            font-size: 0.88em;
            color: var(--fg-muted);
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 2.1em;
            font-weight: 700;
            color: var(--accent-fg);
            font-family: var(--font-mono);
        }
        .table-container {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            border-radius: 10px;
            overflow: hidden;
        }
        .table-wrapper {
            overflow-x: auto;
            overflow-y: auto;
            max-height: 600px;
        }
        .table-wrapper::-webkit-scrollbar { width: 10px; height: 10px; }
        .table-wrapper::-webkit-scrollbar-track { background: transparent; }
        .table-wrapper::-webkit-scrollbar-thumb {
            background: #30363d;
            border-radius: 6px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 760px;
        }
        th, td {
            padding: 12px 15px;
            text-align: right;
            border-bottom: 1px solid var(--border-default);
            font-size: 0.92em;
        }
        td { font-family: var(--font-mono); direction: ltr; text-align: right; }
        td:first-child { font-family: var(--font-sans); direction: rtl; }
        th {
            background: var(--canvas-inset);
            color: var(--fg-muted);
            font-family: var(--font-sans);
            font-weight: 600;
            font-size: 0.85em;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        tr:hover { background: var(--canvas-overlay); }
        .health-bar {
            height: 6px;
            background: #21262d;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 6px;
            width: 100px;
        }
        .health-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--success-emphasis) 0%, var(--success-fg) 100%);
        }
        .back-button {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 24px;
            padding: 10px 20px;
            background: var(--success-emphasis);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.15s;
            font-weight: 600;
            font-size: 0.92em;
        }
        .back-button:hover { background: var(--success-fg); }
        :focus-visible { outline: 2px solid var(--accent-fg); outline-offset: 2px; }
        @media (max-width: 768px) {
            .container { padding: 24px 16px 32px; }
            h1 { font-size: 1.5em; }
            .stat-value { font-size: 1.7em; }
            .table-wrapper { max-height: 420px; }
            th, td { padding: 10px; font-size: 0.85em; }
        }
    </style>
</head>
<body>
    <div class="topbar">
        <a href="/">🛡️ DoH Proxy Pro</a>
    </div>
    <div class="container">
        <h1>📊 آمار زنده سرورها</h1>
        <div class="subtitle">Real-time Server Statistics</div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">تعداد کل سرورها</div>
                <div class="stat-value">${totalProviders}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">سرورهای سالم</div>
                <div class="stat-value">${healthyProviders}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">میانگین سلامت</div>
                <div class="stat-value">${avgHealth.toFixed(1)}%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">درخواست‌های کل</div>
                <div class="stat-value">${globalRequestCount}</div>
            </div>
        </div>

        <div class="table-container">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>رتبه</th>
                            <th>سرور</th>
                            <th>منطقه</th>
                            <th>درصد موفقیت</th>
                            <th>زمان پاسخ</th>
                            <th>سلامت</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${topProviders.map((p, i) => `
                            <tr>
                                <td>${i + 1}</td>
                                <td>${new URL(p.url).hostname}</td>
                                <td>${p.region.toUpperCase()}</td>
                                <td>${p.totalRequests > 0 ? ((p.successCount / p.totalRequests) * 100).toFixed(1) : 0}%</td>
                                <td>${p.avgResponseTime > 0 ? p.avgResponseTime.toFixed(0) : '-'} ms</td>
                                <td>
                                    ${p.healthScore.toFixed(0)}%
                                    <div class="health-bar">
                                        <div class="health-fill" style="width: ${p.healthScore}%"></div>
                                    </div>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>

        <a href="/" class="back-button">← بازگشت به صفحه اصلی</a>
    </div>
</body>
</html>`;
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/dns-query') {
    return handleDNSQuery(request);
  }

  if (path === '/apple') {
    const profile = generateAppleProfile(request.url);
    return new Response(profile, {
      headers: {
        'Content-Type': 'application/x-apple-aspen-config',
        'Content-Disposition': 'attachment; filename="DoH-Profile.mobileconfig"'
      }
    });
  }

  if (path === '/stats') {
    return new Response(generateStatsPage(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }

  const baseUrl = new URL(request.url);
  const workerUrl = `${baseUrl.protocol}//${baseUrl.hostname}/dns-query`;
  const workerHost = baseUrl.hostname;
  const appleProfileUrl = `${baseUrl.protocol}//${baseUrl.hostname}/apple`;
  const statsUrl = `${baseUrl.protocol}//${baseUrl.hostname}/stats`;

  const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DoH Proxy Pro — DNS over HTTPS</title>
    <style>
        :root {
            --canvas-default: #0d1117;
            --canvas-subtle: #161b22;
            --canvas-inset: #010409;
            --canvas-overlay: #1c2128;
            --border-default: #30363d;
            --border-muted: #21262d;
            --fg-default: #e6edf3;
            --fg-muted: #8b949e;
            --fg-subtle: #6e7681;
            --accent-fg: #4493f8;
            --accent-emphasis: #1f6feb;
            --success-fg: #3fb950;
            --success-emphasis: #238636;
            --danger-fg: #f85149;
            --attention-fg: #d29922;
            --done-fg: #a371f7;
            --shadow-card: 0 8px 24px rgba(1, 4, 9, 0.55);
            --topbar-overlay: rgba(13, 17, 23, 0.45);
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
            --font-mono: ui-monospace, "SF Mono", "Segoe UI Mono", "Roboto Mono", Menlo, Consolas, monospace;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        html { scroll-behavior: smooth; }

        body {
            font-family: var(--font-sans);
            background-color: var(--canvas-default);
            background-image: radial-gradient(ellipse 900px 500px at 50% -10%, rgba(31, 111, 235, 0.16), transparent);
            background-repeat: no-repeat;
            color: var(--fg-default);
            line-height: 1.6;
            min-height: 100vh;
        }

        a { color: var(--accent-fg); }

        :focus-visible {
            outline: 2px solid var(--accent-fg);
            outline-offset: 2px;
            border-radius: 4px;
        }

        .topbar {
            position: sticky;
            top: 0;
            z-index: 50;
            background: var(--topbar-overlay);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-default);
        }

        .topbar-inner {
            max-width: 1080px;
            margin: 0 auto;
            padding: 12px 24px;
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 600;
            color: var(--fg-default);
            text-decoration: none;
            font-size: 0.95em;
            white-space: nowrap;
        }

        .brand-mark {
            width: 26px;
            height: 26px;
            border-radius: 7px;
            background: linear-gradient(135deg, var(--accent-emphasis), var(--done-fg));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.85em;
            flex-shrink: 0;
        }

        .topnav {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            overflow-x: auto;
            scrollbar-width: none;
        }

        .topnav::-webkit-scrollbar { display: none; }

        .topnav a {
            color: var(--fg-muted);
            text-decoration: none;
            font-size: 0.85em;
            font-weight: 500;
            padding: 6px 10px;
            border-radius: 6px;
            white-space: nowrap;
            transition: background 0.15s, color 0.15s;
        }

        .topnav a:hover {
            color: var(--fg-default);
            background: var(--canvas-overlay);
        }

        .container {
            max-width: 1080px;
            margin: 0 auto;
            padding: 40px 24px calc(96px + env(safe-area-inset-bottom));
        }

        .hero {
            padding: 8px 0 28px;
        }

        h1.hero-title {
            font-size: 2.3em;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 14px;
            letter-spacing: -0.02em;
            flex-wrap: wrap;
        }

        .badge-pro {
            background: linear-gradient(135deg, var(--success-emphasis), var(--success-fg));
            color: #ffffff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.38em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            vertical-align: middle;
        }

        .hero-subtitle {
            color: var(--fg-muted);
            margin-top: 10px;
            font-size: 1.02em;
            max-width: 640px;
        }

        .shields {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 18px;
        }

        .shield {
            display: inline-flex;
            align-items: center;
            font-size: 0.78em;
            font-weight: 600;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid var(--border-default);
        }

        .shield span {
            padding: 4px 10px;
        }

        .shield .shield-label {
            background: var(--canvas-overlay);
            color: var(--fg-muted);
        }

        .shield .shield-value {
            color: #ffffff;
        }

        .shield.blue .shield-value { background: var(--accent-emphasis); }
        .shield.green .shield-value { background: var(--success-emphasis); }
        .shield.purple .shield-value { background: var(--done-fg); }
        .shield.orange .shield-value { background: #bd561d; }

        .status-bar {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            border-radius: 8px;
            padding: 14px 18px;
            margin: 24px 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status-indicator {
            width: 10px;
            height: 10px;
            background: var(--success-fg);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success-fg);
            flex-shrink: 0;
            animation: pulse 2s ease-in-out infinite;
        }

        @media (prefers-reduced-motion: reduce) {
            .status-indicator { animation: none; }
            html { scroll-behavior: auto; }
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.45; }
        }

        .status-text { color: var(--fg-muted); font-size: 0.92em; }
        .status-text strong { color: var(--success-fg); }

        section { scroll-margin-top: 72px; }

        h2.section-title {
            color: var(--fg-default);
            font-size: 1.35em;
            font-weight: 600;
            margin: 44px 0 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-default);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        h3.card-title {
            color: var(--fg-default);
            font-size: 1.08em;
            margin-bottom: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .card, .info-box, .usage-card {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            border-radius: 10px;
            padding: 18px 20px;
            margin: 16px 0;
        }

        .info-box {
            border-inline-start: 3px solid var(--accent-fg);
            border-start-start-radius: 6px;
            border-end-start-radius: 6px;
        }

        .info-box strong { color: var(--fg-default); }

        .url-container {
            background: var(--canvas-inset);
            border: 1px solid var(--border-default);
            border-radius: 8px;
            padding: 14px 16px;
            margin: 12px 0;
        }

        .url-box {
            font-family: var(--font-mono);
            color: #a5d6ff;
            font-size: 0.98em;
            word-break: break-all;
            direction: ltr;
            text-align: left;
            padding: 4px 0 10px;
        }

        .btn {
            border: 1px solid var(--border-default);
            color: var(--fg-default);
            background: var(--canvas-overlay);
            padding: 6px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 600;
            transition: background 0.15s, border-color 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: var(--font-sans);
        }

        .btn:hover { background: #262c36; border-color: #8b949e; }

        .btn-primary {
            background: var(--success-emphasis);
            border-color: var(--success-emphasis);
            color: #ffffff;
        }

        .btn-primary:hover { background: var(--success-fg); border-color: var(--success-fg); }

        .btn-primary.copied { background: var(--success-fg); border-color: var(--success-fg); }

        .btn-accent {
            background: var(--accent-emphasis);
            border-color: var(--accent-emphasis);
            color: #ffffff;
            text-decoration: none;
        }

        .btn-accent:hover { background: var(--accent-fg); border-color: var(--accent-fg); }

        .btn-purple {
            background: var(--done-fg);
            border-color: var(--done-fg);
            color: #ffffff;
            text-decoration: none;
        }

        .btn-purple:hover { filter: brightness(1.12); }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
            gap: 12px;
            margin: 16px 0;
        }

        .feature-item {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            border-radius: 8px;
            padding: 14px 16px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            transition: border-color 0.15s, transform 0.15s;
        }

        .feature-item:hover {
            border-color: var(--accent-fg);
            transform: translateY(-2px);
        }

        .feature-icon { font-size: 1.2em; flex-shrink: 0; }
        .feature-text { color: var(--fg-default); font-size: 0.92em; }

        .provider-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 10px;
            margin: 16px 0;
        }

        .provider-chip {
            background: var(--canvas-inset);
            border: 1px solid var(--border-muted);
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 0.87em;
            color: var(--fg-muted);
        }

        .provider-chip strong { color: var(--fg-default); }

        .warning-box {
            background: rgba(248, 81, 73, 0.08);
            border: 1px solid rgba(248, 81, 73, 0.4);
            border-inline-start: 3px solid var(--danger-fg);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }

        .warning-box strong { color: #ff7b72; }

        .filter-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 0.9em;
        }

        .filter-table th, .filter-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-default);
            text-align: right;
            vertical-align: top;
        }

        .filter-table th {
            color: var(--fg-muted);
            font-weight: 600;
            font-size: 0.85em;
        }

        .tag {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 9px;
            border-radius: 12px;
            font-size: 0.82em;
            font-weight: 600;
        }

        .tag-yes { background: rgba(63, 185, 80, 0.15); color: var(--success-fg); }
        .tag-no { background: rgba(248, 81, 73, 0.15); color: var(--danger-fg); }

        .success-highlight { color: var(--success-fg); font-weight: 600; }

        .stats-link { text-decoration: none; }

        /* GitHub-style code viewer */
        .code-viewer {
            background: var(--canvas-inset);
            border: 1px solid var(--border-default);
            border-radius: 8px;
            margin: 14px 0;
            overflow: hidden;
        }

        .code-viewer-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 8px 12px;
            background: var(--canvas-subtle);
            border-bottom: 1px solid var(--border-default);
            padding: 8px 8px 8px 14px;
        }

        .code-viewer-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .code-viewer-filename {
            font-family: var(--font-mono);
            font-size: 0.83em;
            color: var(--fg-muted);
            display: flex;
            align-items: center;
            gap: 8px;
            direction: ltr;
        }

        .code-viewer-filename .lang-dot {
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background: var(--attention-fg);
            flex-shrink: 0;
        }

        .code-viewer-body {
            max-height: 340px;
            overflow: auto;
            direction: ltr;
        }

        .code-viewer-body::-webkit-scrollbar { width: 10px; height: 10px; }
        .code-viewer-body::-webkit-scrollbar-track { background: transparent; }
        .code-viewer-body::-webkit-scrollbar-thumb {
            background: #30363d;
            border-radius: 6px;
            border: 2px solid var(--canvas-inset);
        }
        .code-viewer-body::-webkit-scrollbar-thumb:hover { background: #484f58; }

        .code-box {
            font-family: var(--font-mono);
            font-size: 0.82em;
            line-height: 20px;
            white-space: pre;
            color: #a5d6ff;
            padding: 12px 16px;
            display: block;
        }

        .code-line { display: flex; }

        .code-gutter {
            color: var(--fg-subtle);
            text-align: right;
            user-select: none;
            padding-inline-end: 16px;
            min-width: 2.4em;
            flex-shrink: 0;
        }

        .code-content { white-space: pre; }

        .jk { color: #7ee787; }
        .js { color: #a5d6ff; }
        .jn { color: #ffa657; }
        .jb { color: #ff7b72; }
        .jz { color: #ff7b72; }

        .usage-card p { margin: 10px 0; line-height: 1.75; }

        .inline-code {
            background: var(--canvas-inset);
            border: 1px solid var(--border-muted);
            font-family: var(--font-mono);
            font-size: 0.85em;
            padding: 2px 6px;
            border-radius: 4px;
            direction: ltr;
            display: inline-block;
        }

        .block-code {
            background: var(--canvas-inset);
            border: 1px solid var(--border-muted);
            font-family: var(--font-mono);
            font-size: 0.85em;
            padding: 12px 14px;
            border-radius: 6px;
            display: block;
            margin: 10px 0;
            direction: ltr;
            text-align: left;
            color: #a5d6ff;
            overflow-x: auto;
        }

        details.faq-item {
            background: var(--canvas-subtle);
            border: 1px solid var(--border-default);
            border-radius: 8px;
            margin: 10px 0;
            padding: 4px 4px;
        }

        details.faq-item summary {
            cursor: pointer;
            list-style: none;
            padding: 12px 14px;
            font-weight: 600;
            color: var(--fg-default);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        details.faq-item summary::-webkit-details-marker { display: none; }

        details.faq-item summary::before {
            content: "▶";
            font-size: 0.7em;
            color: var(--fg-muted);
            transition: transform 0.15s;
            flex-shrink: 0;
        }

        details.faq-item[open] summary::before { transform: rotate(90deg); }

        details.faq-item .faq-answer {
            padding: 0 14px 16px 38px;
            color: var(--fg-muted);
            line-height: 1.8;
            font-size: 0.94em;
        }

        .footer {
            position: fixed;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 50;
            background: var(--topbar-overlay);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-top: 1px solid var(--border-default);
            text-align: center;
            padding: 10px 16px calc(10px + env(safe-area-inset-bottom));
            color: var(--fg-muted);
            font-size: 0.85em;
        }

        .footer a { text-decoration: none; font-weight: 600; }
        .footer a:hover { text-decoration: underline; }
        .footer .footer-sub { margin-top: 4px; font-size: 0.85em; color: var(--fg-subtle); }

        @media (max-width: 720px) {
            .container { padding: 28px 16px calc(96px + env(safe-area-inset-bottom)); }
            h1.hero-title { font-size: 1.7em; }
            .topbar-inner { padding: 10px 16px; }
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-inner">
            <a href="/" class="brand">
                <span class="brand-mark">🛡️</span>
                <span>DoH Proxy Pro</span>
            </a>
            <nav class="topnav">
                <a href="#overview">معرفی</a>
                <a href="#features">امکانات</a>
                <a href="#providers">سرورها</a>
                <a href="#setup">راه‌اندازی</a>
                <a href="#configs">کانفیگ‌ها</a>
                <a href="#security">امنیت</a>
                <a href="#faq">سوالات</a>
                <a href="${statsUrl}">آمار زنده</a>
            </nav>
        </div>
    </div>

    <div class="container">
        <div class="hero" id="overview">
            <h1 class="hero-title">
                🚀 DoH Proxy
                <span class="badge-pro">Pro</span>
            </h1>
            <p class="hero-subtitle">سرویس شخصی DNS over HTTPS با مسیریابی موازی، Circuit Breaker و انتخاب جغرافیایی سرور — برای دور زدن فیلترینگ در لایه‌ی DNS.</p>

            <div class="shields">
                <span class="shield blue"><span class="shield-label">runtime</span><span class="shield-value">Cloudflare Workers</span></span>
                <span class="shield green"><span class="shield-label">protocol</span><span class="shield-value">DNS-over-HTTPS</span></span>
                <span class="shield purple"><span class="shield-label">providers</span><span class="shield-value">190+</span></span>
                <span class="shield orange"><span class="shield-label">license</span><span class="shield-value">MIT</span></span>
            </div>
        </div>

        <div class="status-bar">
            <div class="status-indicator"></div>
            <div class="status-text">
                <strong>فعال و آماده به کار</strong> — Parallel Racing، Circuit Breaker، Geo-selection و یادگیری تطبیقی در حال اجراست
            </div>
        </div>

        <div class="info-box">
            <strong>این یک سرویس DNS over HTTPS (DoH) پیشرفته با قابلیت‌های ضد سانسور است.</strong><br>
            نسخه‌ی Pro شامل: Parallel DNS Racing، Circuit Breaker Pattern، Geo-based Selection، DNS Padding، ECS Stripping، Negative Caching، Adaptive Timeouts، Enhanced Header Randomization و موارد دیگر.
        </div>

        <a href="${statsUrl}" class="btn btn-primary stats-link">📊 مشاهده آمار زنده سرورها</a>

        <h2 class="section-title">📍 آدرس سرویس شما</h2>
        <div class="url-container">
            <div class="url-box" id="dohUrl">${workerUrl}</div>
            <button class="btn btn-primary" data-copy-target="dohUrl">📋 کپی آدرس</button>
        </div>

        <section id="features">
            <h2 class="section-title">✨ ویژگی‌های پیشرفته</h2>
            <div class="feature-grid">
                <div class="feature-item">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-text">Parallel DNS Racing — همزمان ۱۰ سرور برتر امتحان می‌شود و اولین پاسخ معتبر پذیرفته می‌شود</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🛡️</div>
                    <div class="feature-text">Circuit Breaker Pattern — مدیریت خودکار سرورهای ناسالم و قطع موقت آن‌ها</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🌍</div>
                    <div class="feature-text">Geo-based Selection — انتخاب بهترین سرور بر اساس موقعیت جغرافیایی کاربر</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🧠</div>
                    <div class="feature-text">یادگیری تطبیقی برای امتیازدهی و انتخاب هوشمندانه‌ی سرورها در طول زمان</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🔄</div>
                    <div class="feature-text">Load Balancing هوشمند بر اساس سرعت پاسخ و قابلیت اطمینان هر سرور</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-text">DNS Padding مطابق RFC 8467 — جلوگیری از تحلیل اندازه‌ی بسته‌ها</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🚫</div>
                    <div class="feature-text">ECS Stripping — حذف واقعی EDNS Client Subnet از OPT Record</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">💾</div>
                    <div class="feature-text">Smart Caching با مدیریت خودکار حجم و انقضای کش</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">⏱️</div>
                    <div class="feature-text">Adaptive Timeouts — تنظیم خودکار زمان انتظار بر اساس تاریخچه‌ی هر سرور</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🔁</div>
                    <div class="feature-text">Negative Caching — کش هوشمند پاسخ‌های NXDOMAIN</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">⚙️</div>
                    <div class="feature-text">استفاده از بیش از ۱۹۰ سرور DNS معتبر جهانی</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🎭</div>
                    <div class="feature-text">Enhanced Header Randomization در برابر Fingerprinting سمت provider</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">📊</div>
                    <div class="feature-text">امتیازدهی پویا: ۳۵٪ سلامت، ۳۰٪ سرعت، ۲۰٪ قابلیت اطمینان، ۱۵٪ منطقه</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🔗</div>
                    <div class="feature-text">Request Coalescing — ادغام درخواست‌های هم‌زمان برای یک کوئری برای کاهش تأخیر</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">🌏</div>
                    <div class="feature-text">پشتیبانی کامل از CORS برای درخواست‌های مرورگر</div>
                </div>
                <div class="feature-item">
                    <div class="feature-icon">📡</div>
                    <div class="feature-text">پشتیبانی از JSON DoH API با فرمت application/dns-json</div>
                </div>
            </div>
        </section>

        <section id="providers">
            <h2 class="section-title">🌐 DNS Providers استفاده‌شده</h2>
            <div class="provider-grid">
                <div class="provider-chip"><strong>۱۹۰+</strong> سرور DNS معتبر با پوشش جهانی و انتخاب بر اساس منطقه</div>
                <div class="provider-chip">Cloudflare، Google، Quad9، OpenDNS</div>
                <div class="provider-chip">AdGuard، NextDNS، Mullvad</div>
                <div class="provider-chip">AhaDNS — آمریکا، هلند، لهستان، هند، سنگاپور، استرالیا</div>
                <div class="provider-chip">BlahDNS — فنلاند، ژاپن، آلمان، سنگاپور</div>
                <div class="provider-chip">Pi-DNS — اروپا، آمریکا</div>
                <div class="provider-chip">و ده‌ها سرور دیگر با پوشش جهانی...</div>
            </div>
        </section>

        <div class="info-box">
            <strong>✅ این DoH Proxy چه کارهایی انجام می‌دهد</strong><br><br>
            • <span class="success-highlight">رمزنگاری کامل درخواست‌های DNS</span> از طریق HTTPS<br>
            • <span class="success-highlight">دور زدن DNS Poisoning</span> و جلوگیری از دستکاری پاسخ‌های DNS<br>
            • <span class="success-highlight">باز کردن سایت‌های فیلتر شده در لایه‌ی DNS</span><br>
            • <span class="success-highlight">افزایش حریم خصوصی</span> — ISP نمی‌تواند ببیند به چه دامنه‌هایی کوئری می‌زنید<br>
            • <span class="success-highlight">جلوگیری از Man-in-the-Middle</span> در لایه‌ی DNS<br>
            • <span class="success-highlight">سرعت بالاتر</span> با Racing Mode، Circuit Breaker و Smart Caching
        </div>

        <div class="warning-box" id="security">
            <strong>💡 درک انواع فیلترینگ</strong><br><br>
            فیلترینگ شبکه معمولاً در چند لایه‌ی مستقل انجام می‌شود؛ هرکدام راه‌حل خودشان را دارند:
            <table class="filter-table">
                <thead>
                    <tr><th>لایه‌ی فیلترینگ</th><th>توضیح</th><th>این DoH کافی است؟</th></tr>
                </thead>
                <tbody>
                    <tr>
                        <td>DNS Filtering</td>
                        <td>سایت در سطح پاسخ DNS مسدود یا جعل می‌شود</td>
                        <td><span class="tag tag-yes">✓ بله</span></td>
                    </tr>
                    <tr>
                        <td>SNI Filtering</td>
                        <td>اتصال بر اساس نام دامنه در TLS ClientHello شناسایی و مسدود می‌شود</td>
                        <td><span class="tag tag-no">✗ خیر — نیاز به ECH یا Fragment</span></td>
                    </tr>
                    <tr>
                        <td>IP Blocking</td>
                        <td>آدرس IP مقصد مستقیماً مسدود می‌شود</td>
                        <td><span class="tag tag-no">✗ خیر — نیاز به VPN/Proxy</span></td>
                    </tr>
                    <tr>
                        <td>Deep Packet Inspection</td>
                        <td>بررسی الگوی بسته‌ها فارغ از DNS یا SNI</td>
                        <td><span class="tag tag-no">✗ خیر — نیاز به VPN/Proxy پیشرفته</span></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <strong>نتیجه:</strong> اگر سایت مورد نظر فقط از طریق DNS فیلتر شده، همین DoH کافی است. برای فیلترینگ‌های پیشرفته‌تر (SNI/IP/DPI)، این DoH را همراه با کانفیگ Fragment یا VPN استفاده کنید — این دو در لایه‌های متفاوتی از شبکه عمل می‌کنند و مکمل هم هستند، نه جایگزین هم.
        </div>

        <section id="setup">
            <h2 class="section-title">📱 نحوه استفاده</h2>

            <div class="usage-card">
                <h3 class="card-title">🌐 مرورگرها (Firefox, Chrome, Edge, Brave)</h3>
                <p>بروید به تنظیمات مرورگر ← بخش Privacy یا Security ← DNS over HTTPS ← انتخاب Custom Provider و آدرس بالا را وارد کنید.</p>
                <p><strong>فعال‌سازی ECH در Firefox:</strong></p>
                <p>۱. در آدرس‌بار تایپ کنید: <span class="inline-code">about:config</span><br>
                ۲. جستجو کنید: <span class="inline-code">network.dns.echconfig.enabled</span><br>
                ۳. مقدار را روی true قرار دهید</p>
                <p>با این تنظیمات، بسیاری از سایت‌های فیلتر شده با DNS قابل دسترسی می‌شوند.</p>
            </div>

            <div class="usage-card">
                <h3 class="card-title">📱 اپلیکیشن Intra (اندروید)</h3>
                <p>۱. اپلیکیشن Intra را از Google Play نصب کنید<br>
                ۲. اپلیکیشن را باز کنید<br>
                ۳. روی گزینه‌ی «Configure custom server URL» بزنید<br>
                ۴. آدرس زیر را در قسمت Custom DNS over HTTPS server URL وارد کنید:</p>
                <div class="url-container">
                    <div class="url-box">${workerUrl}</div>
                </div>
                <p>۵. دکمه‌ی ON را فعال کنید</p>
                <p>این تنظیم DNS شما را رمزنگاری می‌کند و سایت‌هایی که فقط با DNS فیلتر شده‌اند را باز می‌کند.</p>
            </div>

            <div class="usage-card">
                <h3 class="card-title">🍎 iOS، iPadOS و macOS</h3>
                <p>برای استفاده در دستگاه‌های اپل، پروفایل شخصی خود را دانلود و نصب کنید:</p>
                <a href="${appleProfileUrl}" class="btn btn-purple">🍎 دانلود پروفایل iOS/macOS</a>
                <p style="margin-top: 14px;"><strong>نحوه نصب:</strong></p>
                <p>• <strong>iOS/iPadOS:</strong> فایل را با Safari دانلود کنید ← Settings ← General ← VPN, DNS & Device Management ← Downloaded Profile ← Install<br>
                • <strong>macOS:</strong> فایل را دانلود کنید ← System Settings ← Privacy &amp; Security ← Profiles ← نصب پروفایل</p>
                <p>پس از نصب، DNS همه‌ی اپلیکیشن‌های شما رمزنگاری می‌شود.</p>
            </div>

            <div class="usage-card">
                <h3 class="card-title">💻 ویندوز ۱۰/۱۱</h3>
                <p>Settings ← Network &amp; Internet ← Properties ← DNS server assignment ← Edit ← Preferred DNS encryption: Encrypted only (DNS over HTTPS) و آدرس بالا را وارد کنید.</p>
            </div>

            <div class="usage-card">
                <h3 class="card-title">🐧 لینوکس (systemd-resolved)</h3>
                <p>۱. ویرایش فایل تنظیمات:</p>
                <code class="block-code">sudo nano /etc/systemd/resolved.conf</code>
                <p>۲. اضافه کردن این خطوط:</p>
                <code class="block-code">[Resolve]<br>DNS=${workerUrl}<br>DNSOverTLS=yes</code>
                <p>۳. ری‌استارت سرویس:</p>
                <code class="block-code">sudo systemctl restart systemd-resolved</code>
            </div>

            <div class="usage-card">
                <h3 class="card-title">🔧 روتر</h3>
                <p>بسته به مدل روتر، ممکن است پشتیبانی از DoH داشته باشد. به تنظیمات DNS روتر خود مراجعه کنید. با تنظیم DoH در روتر، تمام دستگاه‌های متصل به شبکه از DNS رمزنگاری‌شده استفاده می‌کنند.</p>
            </div>
        </section>

        <section id="configs">
            <h2 class="section-title">🔧 کانفیگ‌های Xray</h2>

            <div class="usage-card">
                <h3 class="card-title">کانفیگ ساده (v2rayNG و مشابه)</h3>
                <p>برای استفاده در کلاینت‌های مبتنی بر Xray، می‌توانید از کانفیگ زیر استفاده کنید:</p>
                <div class="code-viewer">
                    <div class="code-viewer-header">
                        <span class="code-viewer-filename"><span class="lang-dot"></span>doh-proxy-simple.json</span>
                        <button class="btn" data-copy-target="xrayConfig">📋 کپی</button>
                    </div>
                    <div class="code-viewer-body">
                        <div class="code-box" id="xrayConfig" data-lang="json">{
  "remarks": "🛡️ DoH Proxy Pro",
  "dns": {
    "servers": [
      {
        "address": "${workerUrl}",
        "skipFallback": true
      }
    ],
    "queryStrategy": "UseIP"
  },
  "inbounds": [
    {
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP"
      },
      "tag": "direct"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "udp,tcp"
      }
    ]
  }
}</div>
                    </div>
                </div>
                <p><strong>نکته:</strong> این کانفیگ DNS شما را امن می‌کند و سایت‌های فیلتر شده با DNS را باز می‌کند.</p>
            </div>

            <div class="usage-card">
                <h3 class="card-title">کانفیگ پیشرفته با Fragment (توصیه می‌شود)</h3>
                <p>این کانفیگ علاوه بر DoH دارای قابلیت Fragment است که در لایه‌ی TCP/TLS به دور زدن فیلترینگ‌های SNI-based کمک می‌کند. این کانفیگ همیشه به‌صورت زنده از مخزن گیت‌هاب پروژه دریافت می‌شود؛ اگر کادر زیر بارگذاری نشد یا کانفیگ قدیمی بود، دکمه‌ی «دریافت کانفیگ جدید» را بزنید:</p>
                <div class="code-viewer">
                    <div class="code-viewer-header">
                        <span class="code-viewer-filename"><span class="lang-dot"></span>doh-proxy-fragment.json</span>
                        <div class="code-viewer-actions">
                            <button class="btn" data-copy-target="xrayFragmentConfig">📋 کپی</button>
                            <button class="btn" data-reload-target="xrayFragmentConfig">🔄 دریافت کانفیگ جدید</button>
                        </div>
                    </div>
                    <div class="code-viewer-body">
                        <div class="code-box" id="xrayFragmentConfig" data-lang="json"><div class="code-line"><span class="code-gutter">1</span><span class="code-content" style="color: var(--fg-muted);">در حال دریافت کانفیگ از گیت‌هاب...</span></div></div>
                    </div>
                </div>
                <p><strong>مزایای کانفیگ Fragment:</strong></p>
                <p>• تکه‌تکه کردن بسته‌ی TLS ClientHello برای دور زدن DPI<br>
                • مکمل DoH؛ روی لایه‌ی متفاوتی از شبکه عمل می‌کند<br>
                • افزایش قابلیت دور زدن فیلترینگ‌های پیشرفته‌تر</p>
            </div>
        </section>

        <h2 class="section-title">🛡️ توصیه‌های امنیتی</h2>
        <div class="info-box">
            <strong>برای حداکثر امنیت و دسترسی:</strong><br><br>
            <strong>سناریو ۱ — فقط فیلترینگ DNS:</strong><br>
            ✓ از این DoH Proxy استفاده کنید<br>
            ✓ بسیاری از سایت‌ها قابل دسترسی می‌شوند<br><br>

            <strong>سناریو ۲ — فیلترینگ پیشرفته‌تر:</strong><br>
            ✓ از این DoH Proxy استفاده کنید<br>
            ✓ ECH را در مرورگر فعال کنید<br>
            ✓ از کانفیگ Fragment در Xray استفاده کنید<br>
            ✓ برای لایه‌های دیگر از VPN استفاده کنید<br><br>

            <strong>نکات عمومی:</strong><br>
            • از مرورگرهای به‌روز استفاده کنید<br>
            • HTTPS را همیشه فعال نگه دارید<br>
            • از نرم‌افزارهای امنیتی معتبر استفاده کنید<br>
            • رمزهای عبور قوی استفاده کنید
        </div>

        <section id="faq">
            <h2 class="section-title">❓ سوالات متداول</h2>

            <details class="faq-item">
                <summary>آیا با این DoH می‌توانم به سایت‌های فیلتر شده دسترسی داشته باشم؟</summary>
                <div class="faq-answer">بله، اگر سایت فقط با DNS فیلتر شده باشد. اگر از روش‌های دیگر (IP blocking، DPI، SNI) فیلتر شده، به Fragment یا VPN هم نیاز دارید.</div>
            </details>

            <details class="faq-item">
                <summary>Fragment چیست و چه کمکی می‌کند؟</summary>
                <div class="faq-answer">Fragment یک تکنیک ضد فیلترینگ است که بسته‌ی TLS ClientHello را در سطح TCP تکه‌تکه می‌کند تا DPI نتواند نام دامنه (SNI) را در یک بسته کامل ببیند. این تکنیک روی خودِ اتصال به مقصد اجرا می‌شود، نه روی DNS، و برای همین مکمل DoH است نه جایگزین آن.</div>
            </details>

            <details class="faq-item">
                <summary>ECH چیست و چگونه کمک می‌کند؟</summary>
                <div class="faq-answer">Encrypted Client Hello نام دامنه (SNI) را در حین TLS Handshake رمزنگاری می‌کند و از فیلترینگ مبتنی بر SNI جلوگیری می‌کند. برای استفاده باید هم مرورگر یا کلاینت و هم سرور مقصد از آن پشتیبانی کنند.</div>
            </details>

            <details class="faq-item">
                <summary>این DoH چه تفاوتی با 1.1.1.1 دارد؟</summary>
                <div class="faq-answer">این DoH Proxy شخصی شماست که روی Cloudflare Worker اجرا می‌شود و به‌جای اتکا به یک provider، همزمان به ۱۰ سرور DNS برتر درخواست می‌فرستد (Parallel Racing)، سرورهای ناسالم را با Circuit Breaker کنار می‌گذارد، بر اساس موقعیت جغرافیایی بهترین سرور را انتخاب می‌کند و نتایج را کش هوشمند می‌کند. در نهایت از همان provider های معتبر استفاده می‌کند اما با لایه‌ای از قابلیت اطمینان و سرعت بیشتر.</div>
            </details>

            <details class="faq-item">
                <summary>آیا این سرویس رایگان است؟</summary>
                <div class="faq-answer">بله، در محدوده‌ی رایگان Cloudflare Workers (۱۰۰,۰۰۰ درخواست در روز) کاملاً رایگان است.</div>
            </details>

            <details class="faq-item">
                <summary>آیا استفاده از این DoH سرعت را کاهش می‌دهد؟</summary>
                <div class="faq-answer">خیر؛ با Cache هوشمند و Racing Mode معمولاً سریع‌ترین پاسخ ممکن را دریافت می‌کنید.</div>
            </details>

            <details class="faq-item">
                <summary>چه تفاوتی بین کانفیگ ساده و کانفیگ Fragment وجود دارد؟</summary>
                <div class="faq-answer">کانفیگ ساده فقط DoH را فعال می‌کند و برای دور زدن فیلترینگ در لایه‌ی DNS کافی است. کانفیگ Fragment علاوه بر DoH، بسته‌های TLS ClientHello را هم تکه‌تکه می‌کند که به دور زدن فیلترینگ‌های پیشرفته‌تر (SNI/DPI) کمک می‌کند. برای حداکثر دسترسی، کانفیگ Fragment توصیه می‌شود.</div>
            </details>

            <details class="faq-item">
                <summary>آیا کسی می‌تواند ببیند من از این سرویس استفاده می‌کنم؟</summary>
                <div class="faq-answer">درخواست‌های DNS شما رمزنگاری‌شده هستند و ISP نمی‌تواند محتوای آن‌ها را ببیند؛ فقط می‌تواند ببیند که به یک سرور Cloudflare متصل هستید.</div>
            </details>

            <details class="faq-item">
                <summary>Parallel Racing چگونه کار می‌کند؟</summary>
                <div class="faq-answer">این سیستم هم‌زمان به ۱۰ سرور DNS برتر (بر اساس امتیازدهی منطقه، سرعت، سلامت و قابلیت اطمینان) درخواست می‌فرستد و اولین پاسخ معتبر را می‌پذیرد. این کار تأخیر را کاهش و قابلیت اطمینان را افزایش می‌دهد.</div>
            </details>

            <details class="faq-item">
                <summary>Request Coalescing چیست؟</summary>
                <div class="faq-answer">وقتی چند کاربر یا برنامه هم‌زمان برای یک دامنه‌ی یکسان کوئری می‌زنند، به‌جای ارسال چند درخواست جداگانه به provider بالادستی، Worker فقط یک درخواست می‌فرستد و پاسخ را بین همه به اشتراک می‌گذارد. این باعث کاهش بار سرور و کاهش تأخیر می‌شود.</div>
            </details>
        </section>

        <div class="footer">
            <p>Designed by: <a href="https://t.me/An0nymou3Bot" target="_blank" rel="noopener noreferrer">Anonymous</a></p>
            <p class="footer-sub">Enhanced Anti-Censorship Version with Parallel Racing Technology</p>
        </div>
    </div>

    <script>
        function fallbackCopy(text) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {}
            document.body.removeChild(textArea);
        }

        function copyToClipboard(elementId, btn) {
            const element = document.getElementById(elementId);
            const text = element.getAttribute('data-raw') || element.textContent;
            const originalHTML = btn.innerHTML;

            const onDone = () => {
                btn.classList.add('copied');
                btn.innerHTML = '✓ کپی شد!';
                setTimeout(() => {
                    btn.classList.remove('copied');
                    btn.innerHTML = originalHTML;
                }, 2000);
            };

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(onDone).catch(() => {
                    fallbackCopy(text);
                    onDone();
                });
            } else {
                fallbackCopy(text);
                onDone();
            }
        }

        document.addEventListener('click', function (event) {
            const reloadBtn = event.target.closest('[data-reload-target]');
            if (reloadBtn) {
                loadDynamicFragmentConfig(reloadBtn);
                return;
            }
            const btn = event.target.closest('[data-copy-target]');
            if (!btn) return;
            copyToClipboard(btn.getAttribute('data-copy-target'), btn);
        });

        function highlightJSONLine(line) {
            const escaped = line
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            return escaped.replace(
                /("[^"]*"(\\s*:)?|\\btrue\\b|\\bfalse\\b|\\bnull\\b|-?\\d+(?:\\.\\d+)?)/g,
                function (match) {
                    let cls = 'jn';
                    if (/^"/.test(match)) {
                        cls = /:$/.test(match) ? 'jk' : 'js';
                    } else if (/^(true|false)$/.test(match)) {
                        cls = 'jb';
                    } else if (/^null$/.test(match)) {
                        cls = 'jz';
                    }
                    return '<span class="' + cls + '">' + match + '</span>';
                }
            );
        }

        function enhanceCodeBlocks() {
            document.querySelectorAll('.code-box[data-lang="json"]').forEach(function (box) {
                const raw = box.textContent.replace(/\\n$/, '');
                const lines = raw.split('\\n');
                const rows = lines.map(function (line, i) {
                    return '<div class="code-line"><span class="code-gutter">' + (i + 1) +
                        '</span><span class="code-content">' + (highlightJSONLine(line) || ' ') + '</span></div>';
                });
                box.setAttribute('data-raw', raw);
                box.innerHTML = rows.join('');
            });
        }

        const WORKER_URL = "${workerUrl}";
        const WORKER_HOST = "${workerHost}";
        const FRAGMENT_CONFIG_SOURCE = 'https://raw.githubusercontent.com/4n0nymou3/cloudflare-doh-proxy/main/configs/doh-proxy-fragment.template.json';

        async function loadDynamicFragmentConfig(triggerBtn) {
            const box = document.getElementById('xrayFragmentConfig');
            if (!box) return;
            const originalBtnHTML = triggerBtn ? triggerBtn.innerHTML : null;
            if (triggerBtn) {
                triggerBtn.disabled = true;
                triggerBtn.innerHTML = '⏳ در حال دریافت...';
            }
            try {
                const response = await fetch(FRAGMENT_CONFIG_SOURCE, { cache: 'no-store' });
                if (!response.ok) throw new Error('HTTP ' + response.status);
                let text = await response.text();
                text = text.split('\${workerUrl}').join(WORKER_URL);
                text = text.split('\${workerHost}').join(WORKER_HOST);
                JSON.parse(text);
                const raw = text.trim();
                const lines = raw.split(String.fromCharCode(10));
                const rows = lines.map(function (line, i) {
                    return '<div class="code-line"><span class="code-gutter">' + (i + 1) +
                        '</span><span class="code-content">' + (highlightJSONLine(line) || ' ') + '</span></div>';
                });
                box.setAttribute('data-raw', raw);
                box.innerHTML = rows.join('');
                if (triggerBtn) {
                    triggerBtn.innerHTML = '✅ به‌روز شد';
                    setTimeout(function () {
                        triggerBtn.disabled = false;
                        triggerBtn.innerHTML = originalBtnHTML;
                    }, 2000);
                }
            } catch (err) {
                box.setAttribute('data-raw', '');
                box.innerHTML = '<div class="code-line"><span class="code-gutter">1</span><span class="code-content" style="color: var(--danger-fg);">دریافت کانفیگ از گیت‌هاب ناموفق بود. با دکمه «دریافت کانفیگ جدید» دوباره تلاش کنید.</span></div>';
                console.warn('Fragment config fetch failed.', err);
                if (triggerBtn) {
                    triggerBtn.disabled = false;
                    triggerBtn.innerHTML = originalBtnHTML;
                }
            }
        }

        document.addEventListener('DOMContentLoaded', function () {
            enhanceCodeBlocks();
            loadDynamicFragmentConfig();
        });
    </script>
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

export async function onRequest(context) {
  return handleRequest(context.request);
}
