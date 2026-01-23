/*
DNS查询服务

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
const CACHE_TTL_SECONDS = 300; // 最大缓存时间（秒）
const MIN_CACHE_TTL_SECONDS = 60; // 最小缓存时间（秒）
const TIMEOUT_MS = 500; // 超时时间（毫秒）
const decoder = new TextDecoder(); // 全局 TextDecoder 实例

export default {
  async fetch(request) {
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
        return new Response(null, { status: 403 });
      }
    }

    // 路由处理
    switch (path) {
      case "/dns-query":
        return await handleDnsQuery(request);
      case "/resolve":
        return await handleDomainResolve(request);
      default:
        return new Response(null, { status: 200 });
    }
  },
};

// 标准 DoH 处理 (RFC 8484)
async function handleDnsQuery(request) {
  let query;

  if (request.method === "GET") {
    const url = new URL(request.url);
    const dns = url.searchParams.get("dns");
    if (!dns) return new Response(null, { status: 400 });

    // Base64URL 解码
    const str = atob(dns.replace(/-/g, '+').replace(/_/g, '/'));
    query = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      query[i] = str.charCodeAt(i);
    }
  } else if (request.method === "POST") {
    if (request.headers.get("content-type") !== "application/dns-message") {
      return new Response(null, { status: 415 });
    }
    query = new Uint8Array(await request.arrayBuffer());
  } else {
    return new Response(null, { status: 405 });
  }

  // 获取上游响应和缓存控制信息
  const { response, upstreamCacheControl } = await forwardDnsQueryWithCacheControl(query);
  if (!response) return new Response(null, { status: 502 });

  // 计算缓存TTL
  let cacheTtl = CACHE_TTL_SECONDS;
  if (upstreamCacheControl) {
    // 解析上游的 max-age 值
    const maxAgeMatch = upstreamCacheControl.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const upstreamMaxAge = parseInt(maxAgeMatch[1], 10);
      cacheTtl = Math.max(MIN_CACHE_TTL_SECONDS, Math.min(upstreamMaxAge, CACHE_TTL_SECONDS));
    }
  }

  return new Response(response, {
    headers: { 
      "Content-Type": "application/dns-message",
      "Cache-Control": `public, max-age=${cacheTtl}`,
      "Access-Control-Allow-Origin": "*"
    }
  });
}

// 域名解析处理
async function handleDomainResolve(request) {
  if (request.method !== "GET") return jsonResponse({}, 405);

  const url = new URL(request.url);
  const domain = url.searchParams.get("name");
  if (!domain) return jsonResponse({}, 400);

  const recordType = url.searchParams.get("type");
  const customDns = url.searchParams.get("server");
  const dnsServers = customDns ? [customDns] : UPSTREAM_DOH_SERVERS;

  if (!recordType) {
    const [aResult, aaaaResult] = await Promise.all([
      queryDnsRecord(domain, "A", dnsServers),
      queryDnsRecord(domain, "AAAA", dnsServers)
    ]);
    return jsonResponse({
      domain,
      types: ["A", "AAAA"],
      status: "success",
      results: { A: aResult, AAAA: aaaaResult }
    });
  } else {
    const result = await queryDnsRecord(domain, recordType, dnsServers);
    if (!result) return jsonResponse({}, 502);
    return jsonResponse(result);
  }
}

async function forwardDnsQueryWithCacheControl(dnsQuery, dnsServers = UPSTREAM_DOH_SERVERS) {
  // 并发请求所有 DNS 服务器，使用 Promise.any 取最快成功的
  const promises = dnsServers.map(async (dohServer) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await fetch(dohServer, {
        method: "POST",
        headers: {
          "Accept": "application/dns-message",
          "Content-Type": "application/dns-message",
        },
        body: dnsQuery,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const upstreamCacheControl = response.headers.get("Cache-Control");
        const responseData = new Uint8Array(await response.arrayBuffer());
        return { response: responseData, upstreamCacheControl };
      } else {
        throw 0; // 抛出轻量级异常，触发 Promise.any 切换
      }
    } catch (error) {
      clearTimeout(timeoutId);
      throw error; // 继续抛出，让 Promise.any 处理
    }
  });

  try {
    return await Promise.any(promises);
  } catch (error) {
    return null; // 所有上游都失败
  }
}

async function forwardDnsQuery(dnsQuery, dnsServers = UPSTREAM_DOH_SERVERS) {
  const result = await forwardDnsQueryWithCacheControl(dnsQuery, dnsServers);
  return result ? result.response : null;
}

async function queryDnsRecord(domain, recordType, dnsServers = UPSTREAM_DOH_SERVERS) {
  const query = buildDnsQuery(domain, recordType);
  if (!query) return null;
  const response = await forwardDnsQuery(query, dnsServers);
  return response ? parseDnsResponse(response, domain, recordType) : null;
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

  const typeCode = typeCodes[recordType.toUpperCase()] || parseInt(recordType);

  if (!typeCode) return null;


  // 使用 TextEncoder 处理域名，速度更快且支持多语言
  const encoder = new TextEncoder();
  const domainParts = domain.split('.').map(part => encoder.encode(part));
  const domainLen = domainParts.reduce((acc, part) => acc + part.length + 1, 1);


  const packet = new Uint8Array(12 + domainLen + 4);
  const view = new DataView(packet.buffer);


  // Header: 12字节
  view.setUint16(0, Math.floor(Math.random() * 65535), false); // ID
  // 0x0100 意味着 RD=1。在大端序下，这行代码已经把 header[2] 设为 1 了。
  view.setUint16(2, 0x0100, false);
  view.setUint16(4, 1, false); // QDCOUNT


  // Question 部分
  let offset = 12;
  for (const part of domainParts) {
    packet[offset++] = part.length;
    packet.set(part, offset);
    offset += part.length;
  }
  packet[offset++] = 0; // 域名结束


  view.setUint16(offset, typeCode, false);
  view.setUint16(offset + 2, 1, false); // QCLASS (IN)


  return packet;
}

function parseDnsResponse(response, domain, recordType) {
  if (response.length < 12) return { domain, type: recordType, status: "error" };
  
  const view = new DataView(response.buffer);
  const rcode = view.getUint16(2, false) & 0x0f;
  
  // RCODE 0 代表成功，3 代表域名不存在
  if (rcode !== 0) return { domain, type: recordType, status: "error" };

  const qcount = view.getUint16(4, false); // 问题数量
  const ancount = view.getUint16(6, false); // 回答数量
  
  // 如果没有回答
  if (ancount === 0) return { domain, type: recordType, status: "no_records", answers: [] };

  const answers = [];
  let offset = 12;

  // 1. 跳过 Question 部分（必须跳过，否则读不到 Answer）
  for(let i=0; i<qcount; i++) {
     offset = skipDnsName(response, offset) + 4;
  }

  // 2. 读取 Answer 部分
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
  let current = offset;
  while (current < response.length) {
    const len = response[current];
    if (len === 0) return current + 1;
    if ((len & 0xc0) === 0xc0) return current + 2; // 指针
    current += len + 1;
  }
  return current;
}

function parseDnsAnswer(response, offset) {
  const nameRes = parseDnsName(response, offset); // 解析名字
  if(!nameRes) return null;
  
  let current = nameRes.nextOffset;
  const view = new DataView(response.buffer);
  
  const type = view.getUint16(current, false);
  const ttl = view.getUint32(current + 4, false);
  const dataLen = view.getUint16(current + 8, false);
  
  current += 10;
  
  let data = null;
  // 解析 IP 或 域名
  switch (type) {
    case 1: // A 记录 (IPv4)
      if (dataLen === 4) {
        data = `${response[current]}.${response[current+1]}.${response[current+2]}.${response[current+3]}`;
      }
      break;
    case 28: // AAAA 记录 (IPv6)
      if (dataLen === 16) {
        data = parseIPv6(response, current);
      }
      break;
    case 5: // CNAME (别名)
      const cnameRes = parseDnsName(response, current);
      data = cnameRes ? cnameRes.name : null;
      break;
    case 15: // MX
      const preference = view.getUint16(current, false);
      const mxRes = parseDnsName(response, current + 2);
      data = { preference, exchange: mxRes ? mxRes.name : null };
      break;
    case 16: // TXT
      const parts = [];
      let txtOffset = 0;
      while (txtOffset < dataLen) {
        const len = response[current + txtOffset];
        parts.push(decoder.decode(response.slice(current + txtOffset + 1, current + txtOffset + 1 + len)));
        txtOffset += 1 + len;
      }
      data = parts.join(""); 
      break;
    case 2: // NS
      const nsRes = parseDnsName(response, current);
      data = nsRes ? nsRes.name : null;
      break;
    case 33: // SRV
      const priority = view.getUint16(current, false);
      const weight = view.getUint16(current + 2, false);
      const port = view.getUint16(current + 4, false);
      const targetRes = parseDnsName(response, current + 6);
      data = { 
        priority, 
        weight, 
        port, 
        target: targetRes ? targetRes.name : null 
      };
      break;
  }

  const typeMap = { 1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 33: "SRV" };
  
  return { 
    name: nameRes.name, 
    type: typeMap[type] || type, 
    ttl: ttl, 
    data: data, 
    nextOffset: current + dataLen 
  };
}

function parseIPv6(response, offset) {
  const parts = [];
  for (let i = 0; i < 8; i++) {
    // 提取每 2 字节并转为 16 进制字符串
    parts.push(((response[offset + i * 2] << 8) | response[offset + i * 2 + 1]).toString(16));
  }

  // 寻找最长的连续零段（RFC 5952 规范）
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  // 只有长度大于 1 的零段才进行 "::" 压缩
  if (bestLen > 1) {
    parts.splice(bestStart, bestLen, "");
    if (bestStart === 0) parts.unshift("");
    if (bestStart + bestLen === 8) parts.push("");
  }
  
  return parts.join(":").replace(/:{3,}/, "::");
}

function parseDnsName(response, offset) {
  const labels = [];
  let current = offset;
  let jumped = false;
  let finalOffset = -1;
  let loops = 0;

  while (true) {
    if (loops++ > 20) break; // 防止死循环
    if (current >= response.length) break;
    
    const len = response[current];
    
    // 遇到 0，结束
    if (len === 0) {
      if (!jumped) finalOffset = current + 1;
      break;
    }
    
    // 遇到指针 (11xxxxxx)
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) finalOffset = current + 2;
      const pointer = ((len & 0x3f) << 8) | response[current + 1];
      current = pointer;
      jumped = true;
      continue;
    }
    
    // 普通标签
    current++;
    let label = "";
    for(let i=0; i<len; i++) label += String.fromCharCode(response[current+i]);
    labels.push(label);
    current += len;
    
    if (!jumped) finalOffset = current;
  }
  
  return { name: labels.join("."), nextOffset: finalOffset };
}
