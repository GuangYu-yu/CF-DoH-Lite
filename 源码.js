export default {
	async fetch(request) {
		const url = new URL(request.url);
		const path = url.pathname;

		// 处理OPTIONS预检请求
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				headers: {
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': '*',
					'Access-Control-Max-Age': '86400'
				}
			});
		}

		// 简单token验证
		const GLOBAL_TOKEN = "getdns";
		const token = url.searchParams.get('token');
		if (!token || token !== GLOBAL_TOKEN) {
			return new Response('Authentication failed', {
				status: 403
			});
		}

		// 路由处理
		switch (path) {
			case '/dns-query':
				return await handleDnsQuery(request);
			case '/resolve':
				return await handleDomainResolve(request);
			default:
				return new Response(`
DNS查询服务

可用端点：
• /dns-query - 标准DNS over HTTPS查询
• /resolve - 简化域名解析（JSON格式）

示例：
curl "https://your-worker.workers.dev/resolve?name=google.com&type=A"
        `, {
					headers: {
						'Content-Type': 'text/plain; charset=utf-8',
						'Access-Control-Allow-Origin': '*'
					}
				});
		}
	}
};

// DNS查询处理
async function handleDnsQuery(request) {
	if (!['POST', 'GET'].includes(request.method)) {
		return new Response('Method Not Allowed', {
			status: 405
		});
	}

	try {
		const dnsQuery = await extractDnsQuery(request);
		if (!dnsQuery || dnsQuery.length < 12) {
			return new Response('Invalid DNS query', {
				status: 400
			});
		}

		const dnsResponse = await forwardDnsQuery(dnsQuery);
		if (!dnsResponse) {
			return new Response('DNS query failed', {
				status: 502
			});
		}

		return new Response(dnsResponse, {
			headers: {
				'Content-Type': 'application/dns-message',
				'Access-Control-Allow-Origin': '*',
				'Cache-Control': 'no-cache, no-store, must-revalidate'
			}
		});
	} catch (error) {
		return new Response('Internal Server Error', {
			status: 500
		});
	}
}

// 域名解析处理
async function handleDomainResolve(request) {
	if (request.method !== 'GET') {
		return jsonResponse({
			error: 'Method Not Allowed'
		}, 405);
	}

	const url = new URL(request.url);
	const domain = url.searchParams.get('name');
	if (!domain) {
		return jsonResponse({
			error: 'Missing name parameter'
		}, 400);
	}

	const recordType = url.searchParams.get('type') || 'all';

	try {
		if (recordType === 'all') {
			const [aResult, aaaaResult] = await Promise.all([
				queryDnsRecord(domain, 'A'),
				queryDnsRecord(domain, 'AAAA')
			]);

			return jsonResponse({
				domain,
				type: 'all',
				status: 'success',
				a_records: aResult || {
					status: 'failed'
				},
				aaaa_records: aaaaResult || {
					status: 'failed'
				}
			});
		}

		const result = await queryDnsRecord(domain, recordType);
		if (!result) {
			return jsonResponse({
				error: 'DNS query failed',
				domain,
				type: recordType
			}, 502);
		}

		return jsonResponse(result);
	} catch (error) {
		return jsonResponse({
			error: 'Internal Server Error',
			message: error.message
		}, 500);
	}
}

// 辅助函数
async function extractDnsQuery(request) {
	if (request.method === 'POST') {
		const contentType = request.headers.get('content-type') || '';

		if (contentType.includes('application/dns-message')) {
			return new Uint8Array(await request.arrayBuffer());
		}

		if (contentType.includes('application/x-www-form-urlencoded')) {
			const formData = await request.text();
			const dnsParam = new URLSearchParams(formData).get('dns');
			return dnsParam ? base64urlToUint8Array(dnsParam) : null;
		}

		return null;
	}

	// GET请求
	const url = new URL(request.url);
	const dnsParam = url.searchParams.get('dns');
	return dnsParam ? base64urlToUint8Array(dnsParam) : null;
}

async function queryDnsRecord(domain, recordType) {
	const query = buildDnsQuery(domain, recordType);
	const response = await forwardDnsQuery(query);
	return response ? parseDnsResponse(response, domain, recordType) : null;
}

function jsonResponse(data, status = 200) {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: {
			'Content-Type': 'application/json',
			'Access-Control-Allow-Origin': '*'
		}
	});
}

// DNS查询转发
async function forwardDnsQuery(dnsQuery) {
	const DOH_SERVERS = [
		'https://cloudflare-dns.com/dns-query',
		'https://dns.google/dns-query'
	];

	const dnsBase64 = uint8ArrayToBase64url(dnsQuery);

	for (const dohServer of DOH_SERVERS) {
		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 5000);

			const response = await fetch(`${dohServer}?dns=${dnsBase64}`, {
				method: 'GET',
				headers: {
					'Accept': 'application/dns-message'
				},
				signal: controller.signal
			});

			clearTimeout(timeoutId);

			if (response.ok) {
				return new Uint8Array(await response.arrayBuffer());
			}
		} catch (error) {
			// 继续尝试下一个服务器
			continue;
		}
	}

	return null;
}

// Base64URL转换
function base64urlToUint8Array(base64url) {
	let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
	while (base64.length % 4 !== 0) base64 += '=';

	try {
		const binaryString = atob(base64);
		return new Uint8Array([...binaryString].map(c => c.charCodeAt(0)));
	} catch {
		return null;
	}
}

function uint8ArrayToBase64url(bytes) {
	const base64 = btoa(String.fromCharCode(...bytes));
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// DNS包构建
function buildDnsQuery(domain, recordType) {
	const typeCodes = {
		'A': 1,
		'AAAA': 28,
		'CNAME': 5,
		'NS': 2
	};
	let typeCode;
	if (!isNaN(recordType)) {
		typeCode = parseInt(recordType);
	} else {
		typeCode = typeCodes[recordType] || 1;
	}

	// 头部
	const header = new Uint8Array(12);
	const view = new DataView(header.buffer);
	view.setUint16(0, Math.floor(Math.random() * 65536), false); // ID
	view.setUint16(2, 0x0100, false); // Flags
	view.setUint16(4, 1, false); // QDCOUNT

	// 域名编码
	const domainBytes = domain.split('.').flatMap(part => [part.length, ...part.split('').map(c => c.charCodeAt(0))]);
	domainBytes.push(0); // 结束符

	// 查询部分
	const question = new Uint8Array([
		...domainBytes,
		(typeCode >> 8) & 0xFF, typeCode & 0xFF, // QTYPE
		0x00, 0x01 // QCLASS (IN)
	]);

	return new Uint8Array([...header, ...question]);
}

// DNS响应解析
function parseDnsResponse(response, domain, recordType) {
	if (response.length < 12) {
		return {
			domain,
			type: recordType,
			status: 'error',
			error: 'Invalid DNS response'
		};
	}

	const view = new DataView(response.buffer);
	const rcode = view.getUint16(2, false) & 0x0F;

	if (rcode !== 0) {
		return {
			domain,
			type: recordType,
			status: 'error',
			error: `DNS error code: ${rcode}`
		};
	}

	const ancount = view.getUint16(6, false);
	if (ancount === 0) {
		return {
			domain,
			type: recordType,
			status: 'no_records',
			answers: []
		};
	}

	const answers = [];
	let offset = skipDnsName(response, 12) + 4; // 跳过查询部分

	for (let i = 0; i < ancount && offset < response.length; i++) {
		const answer = parseDnsAnswer(response, offset);
		if (answer) {
			answers.push(answer);
			offset = answer.nextOffset;
		} else {
			break;
		}
	}

	return {
		domain,
		type: recordType,
		status: 'success',
		count: ancount,
		answers
	};
}

// IPv6地址压缩函数
function compressIPv6(ip) {
	let p = ip.split(':').map(x => x.replace(/^0+/, '') || '0'),
		best = [0, 0],
		cur = [0, 0];
	for (let i = 0; i < 8; i++) p[i] === '0' ? cur[1]++ : (cur = [
		[i, 0]
	], 0);
	for (let i = 0; i < 8; i++) {
		let s = i,
			len = 0;
		while (p[i] === '0') i++, len++;
		if (len > best[1]) best = [s, len];
	}
	if (best[1] > 1) {
		p.splice(best[0], best[1], '');
		if (best[0] === 0) p.unshift('');
		if (best[0] + best[1] === 8) p.push('');
	}
	return p.join(':').replace(/:{3,}/, '::');
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

	const typeNames = {
		1: 'A',
		28: 'AAAA',
		5: 'CNAME',
		2: 'NS'
	};

	return {
		name: nameResult.name,
		type: typeNames[type] || type,
		ttl,
		data,
		nextOffset: offset + rdlength
	};
}

function parseRecordData(response, offset, type, length) {
	const view = new DataView(response.buffer);

	switch (type) {
		case 1: // A记录
			if (length === 4) {
				return `${response[offset]}.${response[offset+1]}.${response[offset+2]}.${response[offset+3]}`;
			}
			break;
		case 28: // AAAA记录
			if (length === 16) {
				const parts = [];
				for (let i = 0; i < 16; i += 2) {
					parts.push(view.getUint16(offset + i, false).toString(16).padStart(4, '0'));
				}
				return compressIPv6(parts.join(':'));
			}
			break;
		case 5: // CNAME记录
		case 2: // NS记录
			const nameResult = parseDnsName(response, offset);
			return nameResult ? nameResult.name : '';
	}

	return '';
}

function parseDnsName(response, offset) {
	const parts = [];
	let currentOffset = offset;

	while (currentOffset < response.length) {
		const length = response[currentOffset];

		if (length === 0) {
			currentOffset++;
			break;
		} else if ((length & 0xC0) === 0xC0) {
			// 指针
			if (currentOffset + 1 >= response.length) return null;
			const pointer = ((length & 0x3F) << 8) | response[currentOffset + 1];
			const pointedName = parseDnsName(response, pointer);
			if (pointedName) parts.push(...pointedName.name.split('.'));
			currentOffset += 2;
			break;
		} else {
			// 标签
			if (currentOffset + length >= response.length) return null;

			let label = '';
			for (let i = 1; i <= length; i++) {
				label += String.fromCharCode(response[currentOffset + i]);
			}
			parts.push(label);
			currentOffset += length + 1;
		}
	}

	return {
		name: parts.join('.'),
		nextOffset: currentOffset
	};
}

function skipDnsName(response, offset) {
	let currentOffset = offset;

	while (currentOffset < response.length) {
		const length = response[currentOffset];

		if (length === 0) {
			currentOffset++;
			break;
		} else if ((length & 0xC0) === 0xC0) {
			currentOffset += 2;
			break;
		} else {
			currentOffset += length + 1;
		}
	}

	return currentOffset;
}
