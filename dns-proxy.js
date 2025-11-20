/*
DNS查询服务 - 纯反向代理实现

可用端点：
• /dns-query - 标准DNS over HTTPS查询
• /resolve - 简化域名解析（JSON格式）

示例：
curl "https://your-worker.workers.dev/resolve?name=google.com&type=A"
curl "https://your-worker.workers.dev/resolve?name=google.com&type=A&server=https://custom-dns.com/dns-query"
*/

const UPSTREAM_DOH_SERVERS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
];

const GLOBAL_AUTH_TOKEN = ""; // token如果为空则无需验证
const CACHE_MAX_AGE_SECONDS = 300; // 缓存有效期（秒）

export default {
  async fetch(request, env, context) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理OPTIONS预检请求
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

    // 简单token验证
    if (GLOBAL_AUTH_TOKEN) {
      const token = url.searchParams.get("token");
      if (!token || token !== GLOBAL_AUTH_TOKEN) {
        return new Response("Authentication failed", { status: 403 });
      }
    }

    // 路由处理
    switch (path) {
      case "/dns-query":
        return await handleDnsQuery(request, context);
      case "/resolve":
        return await handleDomainResolve(request, context);
      default:
        return new Response("DNS Worker is running.", {
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
    }
  },
};

// 标准 DoH 处理 (纯反向代理)
async function handleDnsQuery(request, context) {
  // 构建缓存键
  const cacheKey = new Request(request.url, request);
  
  // 尝试从缓存获取响应
  const cachedResponse = await caches.default.match(cacheKey);
  if (cachedResponse) {
    // 返回缓存的响应，但更新Cache-Control头
    const headers = new Headers(cachedResponse.headers);
    headers.set('Cache-Control', `public, max-age=${CACHE_MAX_AGE_SECONDS}`);
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: headers,
    });
  }

  // 顺序尝试每个DNS服务器，失败时尝试下一个
  for (const dohServer of UPSTREAM_DOH_SERVERS) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 500);

      // 构建上游URL
      const upstreamUrl = new URL(dohServer);
      
      // 如果是GET请求，保留查询参数
      if (request.method === "GET") {
        const requestUrl = new URL(request.url);
        upstreamUrl.search = requestUrl.search;
      }

      // 直接转发请求到上游服务器
      const response = await fetch(upstreamUrl, {
        method: request.method,
        headers: {
          "Accept": "application/dns-message",
          "Content-Type": "application/dns-message",
        },
        body: request.body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        // 创建响应副本用于缓存
        const responseClone = response.clone();
        
        // 设置缓存头
        const cacheHeaders = new Headers(response.headers);
        cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_MAX_AGE_SECONDS}`);
        
        // 创建缓存响应
        const cacheResponse = new Response(responseClone.body, {
          status: response.status,
          statusText: response.statusText,
          headers: cacheHeaders,
        });
        
        // 将响应存入缓存
        context.waitUntil((async () => {
          const cache = await caches.open('dns-cache');
          await cache.put(cacheKey, cacheResponse);
        })());
        
        // 返回响应
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      } else {
        console.warn(`Upstream ${dohServer} returned status ${response.status}`);
      }
    } catch (error) {
      console.error(`DNS query failed for ${dohServer}:`, error.message);
      continue;
    }
  }
  
  return new Response("DNS query failed", { status: 502 });
}

// 域名解析处理
async function handleDomainResolve(request, context) {
  if (request.method !== "GET") return jsonResponse({ error: "Method Not Allowed" }, 405);

  const url = new URL(request.url);
  const domain = url.searchParams.get("name");
  if (!domain) return jsonResponse({ error: "Missing name parameter" }, 400);

  const recordType = url.searchParams.get("type");
  const customDns = url.searchParams.get("server");
  const dnsServer = customDns || UPSTREAM_DOH_SERVERS[0];

  // 构建缓存键
  const cacheKey = new Request(request.url, request);
  
  // 尝试从缓存获取响应
  const cachedResponse = await caches.default.match(cacheKey);
  if (cachedResponse) {
    // 返回缓存的响应，但更新Cache-Control头
    const headers = new Headers(cachedResponse.headers);
    headers.set('Cache-Control', `public, max-age=${CACHE_MAX_AGE_SECONDS}`);
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: headers,
    });
  }

  try {
    let result;
    
    if (!recordType) {
      // 如果没有指定类型，查询A和AAAA记录
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 500);

      // 构建A记录查询URL
      const aUrl = new URL(dnsServer);
      aUrl.searchParams.set("name", domain);
      aUrl.searchParams.set("type", "A");

      // 构建AAAA记录查询URL
      const aaaaUrl = new URL(dnsServer);
      aaaaUrl.searchParams.set("name", domain);
      aaaaUrl.searchParams.set("type", "AAAA");

      // 并行查询A和AAAA记录
      const [aResponse, aaaaResponse] = await Promise.all([
        fetch(aUrl, {
          method: "GET",
          headers: {
            "Accept": "application/dns-message",
          },
          signal: controller.signal,
        }),
        fetch(aaaaUrl, {
          method: "GET",
          headers: {
            "Accept": "application/dns-message",
          },
          signal: controller.signal,
        })
      ]);

      clearTimeout(timeoutId);

      let aResult = null;
      let aaaaResult = null;

      if (aResponse.ok) {
        const aResponseData = new Uint8Array(await aResponse.arrayBuffer());
        aResult = parseDnsResponse(aResponseData, domain, "A");
      }

      if (aaaaResponse.ok) {
        const aaaaResponseData = new Uint8Array(await aaaaResponse.arrayBuffer());
        aaaaResult = parseDnsResponse(aaaaResponseData, domain, "AAAA");
      }

      result = {
        domain,
        types: ["A", "AAAA"],
        status: "success",
        results: { A: aResult, AAAA: aaaaResult }
      };
    } else {
      // 查询指定类型的记录
      const upstreamUrl = new URL(dnsServer);
      upstreamUrl.searchParams.set("name", domain);
      upstreamUrl.searchParams.set("type", recordType);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 500);

      const response = await fetch(upstreamUrl, {
        method: "GET",
        headers: {
          "Accept": "application/dns-message",
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const responseData = new Uint8Array(await response.arrayBuffer());
        result = parseDnsResponse(responseData, domain, recordType);
      } else {
        return jsonResponse({ error: "DNS query failed", domain, type: recordType }, 502);
      }
    }
    
    // 创建响应
    const response = jsonResponse(result);
    
    // 创建响应副本用于缓存
    const responseClone = response.clone();
    
    // 设置缓存头
    const cacheHeaders = new Headers(response.headers);
    cacheHeaders.set('Cache-Control', `public, max-age=${CACHE_MAX_AGE_SECONDS}`);
    
    // 创建缓存响应
    const cacheResponse = new Response(responseClone.body, {
      status: response.status,
      statusText: response.statusText,
      headers: cacheHeaders,
    });
    
    // 将响应存入缓存
    context.waitUntil((async () => {
      const cache = await caches.open('dns-cache');
      await cache.put(cacheKey, cacheResponse);
    })());
    
    return response;
  } catch (error) {
    return jsonResponse({ error: "Internal Server Error", message: error.message }, 500);
  }
}

// DNS查询记录 - 使用纯反向代理方式
async function queryDnsRecord(domain, recordType, dnsServers = UPSTREAM_DOH_SERVERS) {
  // 构建DNS查询URL
  const dnsUrl = new URL(dnsServers[0]);
  dnsUrl.searchParams.set("name", domain);
  dnsUrl.searchParams.set("type", recordType);
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 500);

    // 直接向上游DNS服务器发送GET请求
    const response = await fetch(dnsUrl, {
      method: "GET",
      headers: {
        "Accept": "application/dns-message",
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      // 获取二进制DNS响应
      const responseData = new Uint8Array(await response.arrayBuffer());
      // 解析DNS响应并转换为JSON格式
      return parseDnsResponse(responseData, domain, recordType);
    } else {
      console.warn(`Upstream ${dnsServers[0]} returned status ${response.status}`);
      return null;
    }
  } catch (error) {
    console.error(`DNS query failed for ${dnsServers[0]}:`, error.message);
    return null;
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// 构建 DNS Query 包
function buildDnsQuery(domain, recordType) {
  const typeCodes = { A: 1, AAAA: 28, CNAME: 5, NS: 2, TXT: 16, MX: 15 };
  let typeCode = typeof recordType === 'string' ? typeCodes[recordType.toUpperCase()] : recordType;
  if (!typeCode && !isNaN(recordType)) typeCode = parseInt(recordType);
  if (!typeCode) return null;

  // 头部 (12字节)
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  view.setUint16(0, Math.floor(Math.random() * 65535), false); // ID
  view.setUint16(2, 0x0100, false); // Flags (Standard Query)
  view.setUint16(4, 1, false); // QDCOUNT (1 Question)

  // 域名部分
  const parts = domain.split(".");
  let domainLen = 0;
  for(const p of parts) domainLen += p.length + 1;
  domainLen += 1; // 结尾的 0

  const question = new Uint8Array(domainLen + 4);
  let offset = 0;
    
  for (const part of parts) {
    if (part.length > 63) return null; // 标签过长
    question[offset] = part.length;
    offset++;
    for (let i = 0; i < part.length; i++) {
      question[offset] = part.charCodeAt(i);
      offset++;
    }
  }
  question[offset] = 0; // 结束符
  offset++;

  const qView = new DataView(question.buffer);
  qView.setUint16(offset, typeCode, false); // QTYPE
  qView.setUint16(offset + 2, 1, false); // QCLASS (IN)

  // 合并
  const packet = new Uint8Array(12 + question.length);
  packet.set(header);
  packet.set(question, 12);
  return packet;
}

function parseDnsResponse(response, domain, recordType) {
  if (response.length < 12) return { domain, type: recordType, status: "error", error: "Invalid DNS response" };
  const view = new DataView(response.buffer);
  const rcode = view.getUint16(2, false) & 0x0f;
  if (rcode !== 0) return { domain, type: recordType, status: "error", error: `DNS error code: ${rcode}` };
   
  const ancount = view.getUint16(6, false);
  if (ancount === 0) return { domain, type: recordType, status: "no_records", answers: [] };

  const answers = [];
  let offset = skipDnsName(response, 12) + 4; 

  for (let i = 0; i < ancount && offset < response.length; i++) {
    const answer = parseDnsAnswer(response, offset);
    if (answer) {
      answers.push(answer);
      offset = answer.nextOffset;
    } else {
      break;
    }
  }
  return { domain, type: recordType, status: "success", count: ancount, answers };
}

function skipDnsName(response, offset) {
  let currentOffset = offset;
  while (currentOffset < response.length) {
    const length = response[currentOffset];
    if (length === 0) { currentOffset++; break; }
    else if ((length & 0xc0) === 0xc0) { currentOffset += 2; break; }
    else { currentOffset += length + 1; }
  }
  return currentOffset;
}

function parseDnsAnswer(response, offset) {
  if (offset >= response.length) return null;
  const nameResult = parseDnsName(response, offset);
  if (!nameResult) return null;
  offset = nameResult.nextOffset;
  if (offset + 10 > response.length) return null;
  const view = new DataView(response.buffer);
  const type = view.getUint16(offset, false);
  const ttl = view.getUint32(offset + 4, false);
  const rdlength = view.getUint16(offset + 8, false);
  offset += 10;
  if (offset + rdlength > response.length) return null;
  const data = parseRecordData(response, offset, type, rdlength);
  const typeNames = { 1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 16: "TXT", 15: "MX" };
  return { name: nameResult.name, type: typeNames[type] || type, ttl, data, nextOffset: offset + rdlength };
}

function parseDnsName(response, offset) {
  const parts = [];
  let currentOffset = offset;
  while (currentOffset < response.length) {
    const length = response[currentOffset];
    if (length === 0) { currentOffset++; break; }
    else if ((length & 0xc0) === 0xc0) {
      if (currentOffset + 1 >= response.length) return null;
      const pointer = ((length & 0x3f) << 8) | response[currentOffset + 1];
      if (pointer >= currentOffset) return null;
      const pointedName = parseDnsName(response, pointer);
      if (pointedName) parts.push(...pointedName.name.split("."));
      currentOffset += 2;
      break;
    } else {
      if (currentOffset + 1 + length > response.length) return null;
      let label = "";
      for (let i = 1; i <= length; i++) label += String.fromCharCode(response[currentOffset + i]);
      parts.push(label);
      currentOffset += length + 1;
    }
  }
  return { name: parts.join("."), nextOffset: currentOffset };
}

function parseRecordData(response, offset, type, rdlength) {
  switch (type) {
    case 1: // A
      if (rdlength !== 4) return null;
      return `${response[offset]}.${response[offset+1]}.${response[offset+2]}.${response[offset+3]}`;
    case 28: // AAAA
      if (rdlength !== 16) return null;
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        const part = ((response[offset] << 8) | response[offset+1]).toString(16);
        parts.push(part);
        offset += 2;
      }
      return compressIPv6(parts.join(":"));
    case 5: // CNAME
    case 2: // NS
      const nameResult = parseDnsName(response, offset);
      return nameResult ? nameResult.name : null;
    case 16: // TXT
      let txtOffset = offset;
      let txtData = "";
      while (txtOffset < offset + rdlength) {
        const len = response[txtOffset];
        if (len === 0 || txtOffset + 1 + len > offset + rdlength) break;
        const chunk = String.fromCharCode(...response.slice(txtOffset + 1, txtOffset + 1 + len));
        txtData += (txtData ? " " : "") + chunk;
        txtOffset += 1 + len;
      }
      return txtData;
    case 15: // MX
      if (rdlength < 2) return null;
      const preference = (response[offset] << 8) | response[offset+1];
      const mxNameResult = parseDnsName(response, offset + 2);
      return mxNameResult ? `${preference} ${mxNameResult.name}` : null;
    default:
      return null;
  }
}

function compressIPv6(ipv6) {
  // 简单的IPv6压缩实现
  const parts = ipv6.split(":");
  let maxZeroStart = -1, maxZeroLength = 0;
  let currentZeroStart = -1, currentZeroLength = 0;
   
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (currentZeroStart === -1) {
        currentZeroStart = i;
        currentZeroLength = 1;
      } else {
        currentZeroLength++;
      }
    } else {
      if (currentZeroLength > maxZeroLength) {
        maxZeroStart = currentZeroStart;
        maxZeroLength = currentZeroLength;
      }
      currentZeroStart = -1;
      currentZeroLength = 0;
    }
  }
   
  if (currentZeroLength > maxZeroLength) {
    maxZeroStart = currentZeroStart;
    maxZeroLength = currentZeroLength;
  }
   
  if (maxZeroLength > 1) {
    const compressed = [...parts.slice(0, maxZeroStart), "", ...parts.slice(maxZeroStart + maxZeroLength)];
    return compressed.join(":");
  }
   
  return ipv6;
}
