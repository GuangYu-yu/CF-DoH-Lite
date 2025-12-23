// 上游 DoH 服务器列表
const UPSTREAM_DOH_SERVERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
];

// 配置
const GLOBAL_AUTH_TOKEN = ""; // token如果为空则无需验证
const TIMEOUT_MS = 500; // 超时时间（毫秒）
const CACHE_TTL_SECONDS = 300; // 最大缓存时间（秒）
const MIN_CACHE_TTL_SECONDS = 60; // 最小缓存时间（秒）

export default {
  async fetch(request, env, context) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理 CORS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // Token 验证
    if (GLOBAL_AUTH_TOKEN) {
      const token = url.searchParams.get("token");
      if (!token || token !== GLOBAL_AUTH_TOKEN) {
        return new Response(null, { status: 403 });
      }
    }

    // 路由处理
    switch (path) {
      case "/dns-query":
        return await handleDnsQuery(request, context);
      default:
        return new Response(null, { status: 200 });
    }
  },
};

async function handleDnsQuery(request, context) {
  const method = request.method;

  // 仅允许 GET 和 POST
  if (method !== "GET" && method !== "POST") {
    return new Response(null, { status: 405 });
  }

  const cache = caches.default;
  
  // 缓存读取 (仅限 GET)
  if (method === "GET") {
    const cachedResponse = await cache.match(request);
    if (cachedResponse) {
      const newHeaders = new Headers(cachedResponse.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(cachedResponse.body, {
        status: cachedResponse.status,
        statusText: cachedResponse.statusText,
        headers: newHeaders,
      });
    }
  }

  // 准备请求体 (仅限 POST)
  let requestBody = null;
  if (method === "POST") {
    requestBody = await request.arrayBuffer();
  }

  // 轮询上游服务器
  for (const dohServer of UPSTREAM_DOH_SERVERS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const upstreamUrl = new URL(dohServer);

    // 如果是 GET，将查询参数复制到上游 URL
    if (method === "GET") {
      const requestUrl = new URL(request.url);
      upstreamUrl.search = requestUrl.search;
    }

    // 构建 Fetch 选项
    const fetchOptions = {
      method: method,
      headers: {
        "Accept": "application/dns-message",
      },
      signal: controller.signal,
    };

    // 如果是 POST，附加 Body 和 Content-Type
    if (method === "POST") {
      fetchOptions.headers["Content-Type"] = "application/dns-message";
      fetchOptions.body = requestBody;
    }

    const response = await fetch(upstreamUrl, fetchOptions);

    clearTimeout(timeoutId);

    if (response.ok) {
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      
      // 从上游响应获取缓存控制信息
      const upstreamCacheControl = response.headers.get("Cache-Control");
      let cacheTtl = CACHE_TTL_SECONDS;
      
      if (upstreamCacheControl) {
        // 解析上游的 max-age 值
        const maxAgeMatch = upstreamCacheControl.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const upstreamMaxAge = parseInt(maxAgeMatch[1], 10);
          cacheTtl = Math.max(MIN_CACHE_TTL_SECONDS, Math.min(upstreamMaxAge, CACHE_TTL_SECONDS));
        }
      }
      
      responseHeaders.set("Cache-Control", `public, max-age=${cacheTtl}`);

      // 缓存写入 (仅限 GET)
      if (method === "GET") {
          const responseToCache = response.clone();
          const cacheHeaders = new Headers(responseToCache.headers);
          cacheHeaders.set("Cache-Control", `public, max-age=${cacheTtl}`);
          cacheHeaders.set("Access-Control-Allow-Origin", "*");
          
          const cacheEntry = new Response(responseToCache.body, {
              status: responseToCache.status,
              statusText: responseToCache.statusText,
              headers: cacheHeaders
          });
          
          context.waitUntil(cache.put(request.clone(), cacheEntry));
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }
  }
  
  return new Response(null, { status: 502 });
}
