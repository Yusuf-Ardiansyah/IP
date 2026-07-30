// ==============================================================================
// MAIN V2RAY & PROXY IP CONFIGURATION (MULTIPLE IPS CAN BE COMMA SEPARATED)
// ==============================================================================
const envUUID = '94c33f53-415a-4eb7-b588-4230a45cf72f'; // <-- REPLACE YOUR UUID HERE
let defaultProxyIP = 'proxyip.example.com, cdn.cloudflare.net, 104.16.20.165'; // <-- REPLACE PROXY IP HERE
// ==============================================================================

const Version = '2026-07-29 23:57:34';
let cachedSocks5Whitelist = null, debugLogEnabled = false;
let socks5Whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];

/////////////////////////////////////////////////////// GLOBAL CONSTANTS & UTILS ///////////////////////////////////////////////
const wsEarlyDataMaxBytes = 8 * 1024, wsEarlyDataMaxHeadLen = Math.ceil(wsEarlyDataMaxBytes * 4 / 3) + 4;
const uplinkBundleTargetBytes = 20 * 1024, uplinkQueueMaxBytes = 16 * 1024 * 1024, uplinkQueueMaxItems = 4096;
const downlinkGrainPacketBytes = 32 * 1024, downlinkGrainTailThreshold = 512, downlinkGrainLowWatermarkBytes = Math.max(4096, downlinkGrainTailThreshold * 12), downlinkGrainMaxWaitRounds = 4;
let tcpConcurrentDials = 2, proxyConcurrentDials = 1, preloadRaceDial = false;

/////////////////////////////////////////////////////// SIGNATURE DICTIONARY ///////////////////////////////////////////////
const signatureDict = [
	("ProxyIP").toUpperCase(),
	(String.fromCharCode(67, 109) + "i" + "c").toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];

/////////////////////////////////////////////////////// MAIN ENTRY POINT ///////////////////////////////////////////////
export default {
	async fetch(request, env, ctx) {
		let requestUrlText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const requestUrlAnchorIndex = requestUrlText.indexOf('#');
		const requestUrlMainPart = requestUrlAnchorIndex === -1 ? requestUrlText : requestUrlText.slice(0, requestUrlAnchorIndex);
		if (!requestUrlMainPart.includes('?') && /%3f/i.test(requestUrlMainPart)) {
			const requestUrlAnchorPart = requestUrlAnchorIndex === -1 ? '' : requestUrlText.slice(requestUrlAnchorIndex);
			requestUrlText = requestUrlMainPart.replace(/%3f/i, '?') + requestUrlAnchorPart;
		}
		const url = new URL(requestUrlText);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : envUUID;
		
		const hosts = env.HOST ? (await parseToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		
		debugLogEnabled = ['1', 'true'].includes(env.DEBUG) || debugLogEnabled;
		preloadRaceDial = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial;
		proxyConcurrentDials = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || proxyConcurrentDials);
		tcpConcurrentDials = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || tcpConcurrentDials);
		if (!env.TCP_CONCURRENT_DIAL && tcpConcurrentDials !== 1 && identifyISP(request) === 'cmcc') tcpConcurrentDials = 1;
		
		let defaultProxyFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = await parseToArray(env.PROXYIP);
			defaultProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			defaultProxyFallback = false;
		};
		
		if (cachedSocks5Whitelist === null) {
			if (env.GO2SOCKS5) socks5Whitelist = [...new Set(socks5Whitelist.concat(await parseToArray(env.GO2SOCKS5)))];
			cachedSocks5Whitelist = socks5Whitelist;
		} else socks5Whitelist = cachedSocks5Whitelist;

		if (accessPath === 'version') {
			const requestUUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUUID)) {
				const targetUUID = String(userID).toLowerCase();
				let requestFirst8Sum = 0, targetFirst8Sum = 0;
				for (let i = 0; i < 8; i++) {
					const reqCode = requestUUID.charCodeAt(i);
					requestFirst8Sum += reqCode <= 57 ? reqCode - 48 : reqCode - 87;
					const targetCode = targetUUID.charCodeAt(i);
					targetFirst8Sum += targetCode <= 57 ? targetCode - 48 : targetCode - 87;
				}
				if (requestFirst8Sum === targetFirst8Sum && requestUUID.slice(-12) === targetUUID.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (upgradeHeader === 'websocket') {
			const proxyContext = await getProxyContext(url, userID, defaultProxyIP, defaultProxyFallback);
			log(`[WebSocket] Request hit: ${url.pathname}${url.search}`);
			return await handleWSRequest(request, userID, url, proxyContext);
		} else if (!accessPath.startsWith('admin/') && accessPath !== 'login' && request.method === 'POST') {
			const proxyContext = await getProxyContext(url, userID, defaultProxyIP, defaultProxyFallback);
			const referer = request.headers.get('Referer') || '';
			const hitXHTTPFeature = referer.includes('x_padding', 14) || referer.includes('x_padding=');
			if (!hitXHTTPFeature && contentType.startsWith('application/grpc')) {
				log(`[gRPC] Request hit: ${url.pathname}${url.search}`);
				return await handleGRPCRequest(request, userID, proxyContext);
			}
			log(`[XHTTP] Request hit: ${url.pathname}${url.search}`);
			return await handleXHTTPRequest(request, userID, proxyContext);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
		}

		let camouflagePageUrl = env.URL || 'nginx';
		if (camouflagePageUrl && camouflagePageUrl !== 'nginx' && camouflagePageUrl !== '1101') {
			camouflagePageUrl = camouflagePageUrl.trim().replace(/\/$/, '');
			if (!camouflagePageUrl.match(/^https?:\/\//i)) camouflagePageUrl = 'https://' + camouflagePageUrl;
			if (camouflagePageUrl.toLowerCase().startsWith('http://')) camouflagePageUrl = 'https://' + camouflagePageUrl.substring(7);
			try { const u = new URL(camouflagePageUrl); camouflagePageUrl = u.protocol + '//' + u.host } catch (e) { camouflagePageUrl = 'nginx' }
		}
		
		try {
			const proxyURL = new URL(camouflagePageUrl), newReqHeaders = new Headers(request.headers);
			newReqHeaders.set('Host', proxyURL.host);
			newReqHeaders.set('Referer', proxyURL.origin);
			newReqHeaders.set('Origin', proxyURL.origin);
			if (!newReqHeaders.has('User-Agent') && UA && UA !== 'null') newReqHeaders.set('User-Agent', UA);
			const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, { method: request.method, headers: newReqHeaders, body: request.body, cf: request.cf });
			const respContentType = proxyResponse.headers.get('content-type') || '';
			if (/text|javascript|json|xml/.test(respContentType)) {
				const responseContent = (await proxyResponse.text()).replaceAll(proxyURL.host, url.host);
				return new Response(responseContent, { status: proxyResponse.status, headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return proxyResponse;
		} catch (error) { }
		return new Response("V2Ray Engine Running - IP Rotation Active", { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
	}
};

/////////////////////////////////////////////////////////////////////// XHTTP DATA TRANSFER ///////////////////////////////////////////////
async function handleXHTTPRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readFirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && proxyContext.proxyType === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(buildLocal204Response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	let currentWriteSocket = null;
	let remoteWriter = null;
	const invalidateRemoteConnection = () => invalidateTCPGeneration(remoteConnWrapper);
	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const getRemoteWriter = () => {
		const socket = remoteConnWrapper.socket;
		if (!socket) return null;
		if (socket !== currentWriteSocket) {
			releaseRemoteWriter();
			currentWriteSocket = socket;
			remoteWriter = socket.writable.getWriter();
		}
		return remoteWriter;
	};

	let xhttpUplinkWriteQueue = null;
	const trojanUdpContext = { cache: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let udpRespHeader = firstPacket.respHeader;
			const xhttpBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						isClosed = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (isClosed) return;
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const uplinkWriteQueue = xhttpUplinkWriteQueue = createUplinkWriteQueue({
				getWriter: getRemoteWriter,
				getConnectionTask: () => remoteConnWrapper.connectingPromise,
				releaseWriter: releaseRemoteWriter,
				retryConnect: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConnection: () => {
					invalidateRemoteConnection();
					closeSocketQuietly(xhttpBridge);
				},
				queueName: 'XHTTP_Uplink'
			});

			const writeToRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.writeAndWait(payload, allowRetry);
			};

			let forwardingFailed = false;
			try {
				if (firstPacket.isUDP) {
					if (firstPacket.protocol === 'trojan') {
						trojanUdpContext.targetHost = firstPacket.hostname;
						trojanUdpContext.targetPort = firstPacket.port;
						if (trojanUdpContext.proxyAddress) await forwardTrojanUdpData(firstPacket.originalData, xhttpBridge, trojanUdpContext, request);
					}
					if (!(firstPacket.protocol === 'trojan' && trojanUdpContext.proxyAddress) && firstPacket.rawData?.byteLength) {
						if (firstPacket.protocol === 'trojan') await forwardTrojanUdpData(firstPacket.rawData, xhttpBridge, trojanUdpContext, request);
						else await forwardDataUdp(firstPacket.rawData, xhttpBridge, udpRespHeader, request);
						udpRespHeader = null;
					}
				} else {
					await forwardDataTCP(firstPacket.hostname, firstPacket.port, firstPacket.rawData, xhttpBridge, firstPacket.respHeader, remoteConnWrapper, yourUUID, request, proxyContext, firstPacket.protocol === 'trojan', firstPacket.originalData);
				}

				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (firstPacket.isUDP) {
						if (firstPacket.protocol === 'trojan') await forwardTrojanUdpData(value, xhttpBridge, trojanUdpContext, request);
						else await forwardDataUdp(value, xhttpBridge, udpRespHeader, request);
						udpRespHeader = null;
					} else {
						if (!(await writeToRemote(value))) throw new Error('Remote socket is not ready');
					}
				}

				if (!firstPacket.isUDP) {
					await uplinkWriteQueue.waitEmpty();
					const writer = getRemoteWriter();
					if (writer) {
						try { await writer.close() } catch (e) { }
					}
				}
			} catch (err) {
				forwardingFailed = true;
				log(`[XHTTP Forwarding] Processing failed: ${err?.message || err}`);
				closeSocketQuietly(xhttpBridge);
			} finally {
				const keepTrojanUdpProxyDownlink = !forwardingFailed && firstPacket.isUDP && firstPacket.protocol === 'trojan' && trojanUdpContext.proxyAddress && trojanUdpContext.proxySocket;
				uplinkWriteQueue.clearQueue();
				if (forwardingFailed) invalidateRemoteConnection();
				releaseRemoteWriter();
				if (!keepTrojanUdpProxyDownlink) try { trojanUdpContext.proxySocket?.close() } catch (e) { }
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			xhttpUplinkWriteQueue?.clearQueue();
			invalidateRemoteConnection();
			try { trojanUdpContext.proxySocket?.close() } catch (e) { }
			releaseRemoteWriter();
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

// ==============================================================================
// UTILITY CORE & PROTOCOL HANDLERS (XHTTP & gRPC)
// ==============================================================================

function identifyISP(request) {
	const cf = request?.cf;
	const asnMap = {
		'4134': 'ct', '4809': 'ct', '4811': 'ct', '4812': 'ct', '4815': 'ct',
		'4837': 'cu', '4814': 'cu', '9929': 'cu', '17623': 'cu', '17816': 'cu',
		'9808': 'cmcc', '24400': 'cmcc', '56040': 'cmcc', '56041': 'cmcc', '56044': 'cmcc',
	};
	const ispKeywords = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const orgName = String(cf?.asOrganization || '').toLowerCase();
	const hitISP = ispKeywords.find(({ pattern }) => pattern.test(orgName))?.code;
	return hitISP || asnMap[String(cf?.asn || '')] || 'cf';
}

async function parseToArray(content) {
	var replacedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (replacedContent.charAt(0) == ',') replacedContent = replacedContent.slice(1);
	if (replacedContent.charAt(replacedContent.length - 1) == ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);
	const addrArray = replacedContent.split(',');
	return addrArray;
}

function log(...args) {
	if (debugLogEnabled) console.log(...args);
}

function getValidDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function invalidateTCPGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function startTCPGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.stopAndFlush?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function readFirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVlessFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { status: 'need_more' };
		if (!uuidByteMatch(data, 1, token)) return { status: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { status: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { status: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { status: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { status: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { status: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };

		return {
			status: 'ok',
			result: {
				protocol: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				originalData: null,
			}
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashBytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { status: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { status: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { status: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { status: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { status: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { status: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { status: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { status: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { status: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { status: 'invalid' };

		if (!hostname) return { status: 'invalid' };
		if (length < cursor + 4) return { status: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { status: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			status: 'ok',
			result: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				originalData: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (trojanResult.status === 'ok') return { ...trojanResult.result, reader };

		const vlessResult = tryParseVlessFirstPacket(currentData);
		if (vlessResult.status === 'ok') return { ...vlessResult.result, reader };

		if (trojanResult.status === 'invalid' && vlessResult.status === 'invalid') return null;
	}

	const finalData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(finalData);
	if (finalTrojanResult.status === 'ok') return { ...finalTrojanResult.result, reader };
	const finalVlessResult = tryParseVlessFirstPacket(finalData);
	if (finalVlessResult.status === 'ok') return { ...finalVlessResult.result, reader };
	return null;
}

async function handleGRPCRequest(request, yourUUID, proxyContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConnection = () => invalidateTCPGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUdpContext = { cache: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	let checkIsTrojan = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let grpcUplinkWriteQueue = null;
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const downlinkCacheLimit = downlinkGrainPacketBytes;
	const downlinkFlushInterval = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let isClosed = false;
			let sendQueue = [];
			let queueByteCount = 0;
			let flushTimer = null;
			let flushMicrotaskQueued = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (isClosed) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytesArray = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytesArray.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytesArray.push(remaining);
					const lenBytes = new Uint8Array(lenBytesArray);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					sendQueue.push(frame);
					queueByteCount += frame.byteLength;
					scheduleFlushSendQueue();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					flushSendQueue(true);
					isClosed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const flushSendQueue = (force = false) => {
				flushMicrotaskQueued = false;
				if (flushTimer) {
					clearTimeout(flushTimer);
					flushTimer = null;
				}
				if ((!force && isClosed) || queueByteCount === 0) return;
				const out = new Uint8Array(queueByteCount);
				let offset = 0;
				for (const item of sendQueue) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				sendQueue = [];
				queueByteCount = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					isClosed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const scheduleFlushSendQueue = () => {
				if (queueByteCount >= downlinkCacheLimit) {
					flushSendQueue();
					return;
				}
				if (flushMicrotaskQueued || flushTimer) return;
				flushMicrotaskQueued = true;
				queueMicrotask(() => {
					flushMicrotaskQueued = false;
					if (isClosed || queueByteCount === 0 || flushTimer) return;
					flushTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
				});
			};

			const closeConnection = () => {
				if (isClosed) return;
				grpcUplinkWriteQueue?.clearQueue();
				invalidateRemoteConnection();
				flushSendQueue(true);
				isClosed = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (flushTimer) clearTimeout(flushTimer);
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
				try { reader.releaseLock() } catch (e) { }
				try { trojanUdpContext.proxySocket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
			};

			const uplinkWriteQueue = grpcUplinkWriteQueue = createUplinkWriteQueue({
				getWriter: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== currentWriteSocket) {
						releaseRemoteWriter();
						currentWriteSocket = socket;
						remoteWriter = socket.writable.getWriter();
					}
					return remoteWriter;
				},
				getConnectionTask: () => remoteConnWrapper.connectingPromise,
				releaseWriter: releaseRemoteWriter,
				retryConnect: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConnection,
				queueName: 'gRPC_Uplink'
			});

			const writeToRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.writeAndWait(payload, allowRetry);
			};

			let forwardingFailed = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + currentChunk.length);
					merged.set(pending, 0);
					merged.set(currentChunk, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varintValid = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varintValid = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varintValid) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (checkIsTrojan) await forwardTrojanUdpData(payload, grpcBridge, trojanUdpContext, request);
							else await forwardDataUdp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await writeToRemote(payload))) throw new Error('Remote socket is not ready');
						} else {
							const firstPacketBytes = convertToUint8Array(payload);
							if (checkIsTrojan === null) checkIsTrojan = firstPacketBytes.byteLength >= 58 && firstPacketBytes[56] === 0x0d && firstPacketBytes[57] === 0x0a;
							if (checkIsTrojan) {
								const parseResult = parseTrojanRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = parseResult;
								log(`[gRPC] Trojan First Packet: ${hostname}:${port} | UDP: ${isUDP ? 'Yes' : 'No'}`);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
									grpcBridge.send(buildLocal204Response());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									trojanUdpContext.targetHost = hostname;
									trojanUdpContext.targetPort = port;
									if (trojanUdpContext.proxyAddress) await forwardTrojanUdpData(firstPacketBytes, grpcBridge, trojanUdpContext, request);
									else if (getValidDataLength(rawClientData) > 0) await forwardTrojanUdpData(rawClientData, grpcBridge, trojanUdpContext, request);
								} else {
									await forwardDataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext, true, firstPacketBytes);
								}
							} else {
								checkIsTrojan = false;
								const parseResult = parseVlessRequest(firstPacketBytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
								const { port, hostname, version, isUDP, rawClientData } = parseResult;
								log(`[gRPC] VLESS First Packet: ${hostname}:${port} | UDP: ${isUDP ? 'Yes' : 'No'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
									grpcBridge.send(buildLocal204Response(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (checkIsTrojan) await forwardTrojanUdpData(rawData, grpcBridge, trojanUdpContext, request);
									else await forwardDataUdp(rawData, grpcBridge, null, request);
								}
								else await forwardDataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, proxyContext);
							}
						}
					}
					flushSendQueue();
				}
				await uplinkWriteQueue.waitEmpty();
			} catch (err) {
				forwardingFailed = true;
				log(`[gRPC Forwarding] Processing failed: ${err?.message || err}`);
			} finally {
				const keepTrojanUdpProxyDownlink = !forwardingFailed && isDnsQuery && checkIsTrojan && trojanUdpContext.proxyAddress && trojanUdpContext.proxySocket;
				if (keepTrojanUdpProxyDownlink) {
					uplinkWriteQueue.clearQueue();
					invalidateRemoteConnection();
					releaseRemoteWriter();
					try { reader.releaseLock() } catch (e) { }
				} else {
					closeConnection();
				}
			}
		},
		cancel() {
			grpcUplinkWriteQueue?.clearQueue();
			invalidateRemoteConnection();
			try { trojanUdpContext.proxySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

// ==============================================================================
// BAGIAN 3: WEBSOCKET HANDLER, FORWARDING, DNS DoH, & TLS/PROXY CLIENTS
// ==============================================================================

const vlessTextDecoder = new TextDecoder();
const trojanTextDecoder = new TextDecoder();
const uuidByteCache = new Map();

function readHexNibble(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getUuidBytes(uuid) {
	const key = String(uuid || '');
	let cached = uuidByteCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexNibble(clean.charCodeAt(i * 2));
		const low = readHexNibble(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (uuidByteCache.size >= 32) uuidByteCache.clear();
	uuidByteCache.set(key, bytes);
	return bytes;
}

function uuidByteMatch(data, offset, uuid) {
	const expected = getUuidBytes(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function mergeByteData(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(convertToUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function webSocketSendAndWait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function createRequestTcpConnector(request) {
	const reqObj = /** @type {any} */ (request);
	const fetcher = reqObj?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildLocal204Response(respHeader = null) {
	const local204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return local204Response;
	const protocolRespHeader = convertToUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + local204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(local204Response, protocolRespHeader.byteLength);
	return response;
}

function buildWSLocal204Response(respHeader = null) {
	const wsLocal204Response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (getValidDataLength(respHeader) === 0) return wsLocal204Response;
	const protocolRespHeader = convertToUint8Array(respHeader);
	const response = new Uint8Array(protocolRespHeader.byteLength + wsLocal204Response.byteLength);
	response.set(protocolRespHeader, 0);
	response.set(wsLocal204Response, protocolRespHeader.byteLength);
	return response;
}

function parseTrojanProxyAddress(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('Trojan proxy only supports host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const match = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!match) throw new Error('Invalid IPv6 Trojan proxy address');
		hostname = match[1];
		portText = match[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('Trojan proxy only supports host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid Trojan proxy port');
	return { hostname, port };
}

function extractTrojanProxyHandshakeData(firstPacketData, rawData) {
	const firstPacket = convertToUint8Array(firstPacketData);
	const payload = convertToUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const handshakeLen = firstPacket.byteLength - payload.byteLength;
	if (handshakeLen <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[handshakeLen + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, handshakeLen);
}

function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}
	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);
	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}
	const decoder = new TextDecoder();
	return decoder.decode(data);
}

const proxyProtocolDefaultPort = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function getProxyDefaultPort(type) {
	return proxyProtocolDefaultPort[String(type || '').toLowerCase()] || 80;
}

const socks5AccountBase64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, ipv6BracketsRegex = /^\[.*\]$/;
function getSocks5Account(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && socks5AccountBase64Regex.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('Invalid SOCKS format: auth must be "username:password"');

	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('Invalid SOCKS format: port must be numeric');
	if (hostname.includes(":") && !ipv6BracketsRegex.test(hostname)) throw new Error('Invalid SOCKS format: IPv6 must be in brackets, e.g., [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getProxyContext(url, uuid, defaultProxyIP = '', defaultProxyFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let proxyIP = defaultProxyIP, enableSocks5Proxy = null, enableSocks5GlobalProxy = false, mySocks5Account = '', parsedSocks5Address = {}, enableProxyFallback = defaultProxyFallback;
	const proxyContext = { trojanProxyAddress: null, proxyIP, proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: {}, proxyFallback: enableProxyFallback };
	const saveSnapshot = () => {
		proxyContext.proxyIP = proxyIP;
		proxyContext.proxyType = enableSocks5Proxy;
		proxyContext.proxyAccount = mySocks5Account;
		proxyContext.proxyGlobal = enableSocks5GlobalProxy;
		proxyContext.proxyParams = { ...parsedSocks5Address };
		proxyContext.proxyFallback = enableProxyFallback;
	};

	const chainedProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainedProxyPathMatch) {
		try {
			const chainedProxyPlaintext = base64SecretDecode(chainedProxyPathMatch[1], uuid);
			const { type, ...chainedProxyAddress } = JSON.parse(chainedProxyPlaintext);
			if (!type || !proxyProtocolDefaultPort[String(type).toLowerCase()]) throw new Error('Invalid chained proxy type');
			if (!chainedProxyAddress.hostname || !chainedProxyAddress.port) throw new Error('Chained proxy missing hostname or port');
			mySocks5Account = '';
			proxyIP = 'chained_proxy';
			enableProxyFallback = false;
			enableSocks5GlobalProxy = true;
			enableSocks5Proxy = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainedProxyAddress.username,
				password: chainedProxyAddress.password,
				hostname: chainedProxyAddress.hostname,
				port: Number(chainedProxyAddress.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('Invalid chained proxy port');
			saveSnapshot();
			return proxyContext;
		} catch (err) {
			console.error('Failed to parse chained proxy params:', err.message);
		}
	}

	mySocks5Account = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	enableSocks5GlobalProxy = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
	else if (searchParams.get('http')) enableSocks5Proxy = 'http';
	else if (searchParams.get('https')) enableSocks5Proxy = 'https';
	else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
	else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';

	const parseProxyURL = (value, forceGlobal = true) => {
		const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!match) return false;
		enableSocks5Proxy = match[1].toLowerCase();
		mySocks5Account = match[2].split('/')[0];
		if (forceGlobal) enableSocks5GlobalProxy = true;
		return true;
	};

	const setProxyIP = (value) => {
		proxyIP = value;
		enableSocks5Proxy = null;
		enableProxyFallback = false;
	};

	const extractPathValue = (value) => {
		if (!value.includes('://')) {
			const slashIndex = value.indexOf('/');
			return slashIndex > 0 ? value.slice(0, slashIndex) : value;
		}
		const protoSplit = value.split('://');
		if (protoSplit.length !== 2) return value;
		const slashIndex = protoSplit[1].indexOf('/');
		return slashIndex > 0 ? `${protoSplit[0]}://${protoSplit[1].slice(0, slashIndex)}` : value;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			proxyContext.trojanProxyAddress = parseTrojanProxyAddress(trojanPathMatch[1]);
		} catch (err) {
			proxyContext.trojanProxyAddress = null;
		}
	}

	const queryProxyIP = searchParams.get('proxyip');
	if (queryProxyIP !== null) {
		if (!parseProxyURL(queryProxyIP)) {
			setProxyIP(queryProxyIP);
			saveSnapshot();
			return proxyContext;
		}
	} else {
		let match = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (match) {
			const type = match[1].toLowerCase();
			enableSocks5Proxy = type === 'sock' || type === 'socks' ? 'socks5' : type;
			mySocks5Account = match[2].split('/')[0];
			enableSocks5GlobalProxy = true;
		} else if ((match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const type = match[1].toLowerCase();
			mySocks5Account = match[2].split('/')[0];
			enableSocks5Proxy = type.includes('sstp') ? 'sstp' : (type.includes('turn') ? 'turn' : (type.includes('https') ? 'https' : (type.includes('http') ? 'http' : 'socks5')));
			if (type.startsWith('g')) enableSocks5GlobalProxy = true;
		} else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathProxyValue = extractPathValue(match[2]);
			if (!parseProxyURL(pathProxyValue)) {
				setProxyIP(pathProxyValue);
				saveSnapshot();
				return proxyContext;
			}
		}
	}

	if (!mySocks5Account) {
		enableSocks5Proxy = null;
		saveSnapshot();
		return proxyContext;
	}

	try {
		parsedSocks5Address = await getSocks5Account(mySocks5Account, getProxyDefaultPort(enableSocks5Proxy));
		if (searchParams.get('socks5')) enableSocks5Proxy = 'socks5';
		else if (searchParams.get('http')) enableSocks5Proxy = 'http';
		else if (searchParams.get('https')) enableSocks5Proxy = 'https';
		else if (searchParams.get('turn')) enableSocks5Proxy = 'turn';
		else if (searchParams.get('sstp')) enableSocks5Proxy = 'sstp';
		else enableSocks5Proxy = enableSocks5Proxy || 'socks5';
	} catch (err) {
		enableSocks5Proxy = null;
	}
	saveSnapshot();
	return proxyContext;
}

function createGrainContainer(capacity, copyBundleResult = false) {
	let queue = [];
	let head = 0;
	let byteCount = 0;
	let bundleBuffer = null;

	const isEmpty = () => head >= queue.length;
	const compress = () => {
		if (head > 32 && head * 2 >= queue.length) {
			queue = queue.slice(head);
			head = 0;
		}
	};
	const takeOut = () => {
		if (isEmpty()) return null;
		const item = queue[head];
		queue[head++] = undefined;
		byteCount -= item.chunk.byteLength;
		compress();
		return item;
	};

	return {
		get byteCount() { return byteCount },
		get itemCount() { return queue.length - head },
		get isEmpty() { return isEmpty() },
		clear(processItem = null) {
			if (processItem) {
				for (let i = head; i < queue.length; i++) {
					if (queue[i]) processItem(queue[i]);
				}
			}
			queue = [];
			head = 0;
			byteCount = 0;
		},
		store(item) {
			if (!item?.chunk?.byteLength) return false;
			queue.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		bundle() {
			const first = takeOut();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= capacity) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = head;
			while (end < queue.length) {
				const nextBytes = totalBytes + queue[end].chunk.byteLength;
				if (nextBytes > capacity) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === head) return { chunk: first.chunk, items };

			const output = (bundleBuffer ||= new Uint8Array(capacity));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (head < end) {
				const next = queue[head];
				queue[head++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compress();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: copyBundleResult ? bundled.slice() : bundled, items };
		}
	};
}

function createUplinkWriteQueue({ getWriter, getConnectionTask = null, releaseWriter, retryConnect, closeConnection, queueName = 'UplinkQueue' }) {
	const grain = createGrainContainer(uplinkBundleTargetBytes);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${queueName}: queue closed`) : null);
		if (closeErr) {
			grain.clear(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clear();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.bundle();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const waitAvailableWriter = async () => {
		let writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnectionTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await waitAvailableWriter();
					if (closed) break;
					if (!writer) throw new Error(`${queueName}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
						await retryConnect();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${queueName}] Write failed: ${err?.message || err}`);
			try { closeConnection?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter() && !getConnectionTask?.()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.itemCount + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxItems) {
			closed = true;
			const err = Object.assign(new Error(`${queueName}: upload queue overflow`), { isQueueOverflow: true });
			clear(err);
			try { closeConnection?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.store({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		write(data, allowRetry = true) { return enqueue(data, allowRetry, false); },
		writeAndWait(data, allowRetry = true) { return enqueue(data, allowRetry, true); },
		async waitEmpty() {
			if (!grain.byteCount && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		clearQueue() { closed = true; clear(); }
	};
}

function createDownlinkGrainSender(webSocket, headerData = null, isActive = null) {
	const packetCap = downlinkGrainPacketBytes;
	const tailBytes = downlinkGrainTailThreshold;
	const grain = createGrainContainer(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopStarted = false;
	let activeSends = 0;
	let activeDirectSends = 0;
	let activeSendError = null;
	let activeSendWaiters = [];
	
	const waitActiveSends = () => {
		if (!activeSends && !activeDirectSends) return Promise.resolve();
		return new Promise(resolve => activeSendWaiters.push(resolve));
	};
	const markSendComplete = () => {
		if (activeSends || activeDirectSends || !activeSendWaiters.length) return;
		const resolvers = activeSendWaiters;
		activeSendWaiters = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clear();
		throw err;
	};
	const isSenderValid = () => forceDrain || !isActive || isActive();
	const closeActiveConnection = () => {
		if (isSenderValid()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!isSenderValid()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = appendResponseHeader(chunk);
		await webSocketSendAndWait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally { if (directSendPromise === sendTask) directSendPromise = null; }
	};

	const appendResponseHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!isSenderValid()) {
			grain.clear();
			return;
		}
		const sendTask = (async () => {
			for (; ;) {
				if (!isSenderValid()) { grain.clear(); break; }
				const packed = grain.bundle();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = sendTask.catch(err => { activeSendError ||= err; throw err; }).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!isSenderValid()) { grain.clear(); return; }
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveConnection); return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!isSenderValid()) { grain.clear(); return; }
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) { flush().catch(closeActiveConnection); return; }
			if (waitRounds < downlinkGrainMaxWaitRounds && (generation !== scheduledGeneration || grain.byteCount < downlinkGrainLowWatermarkBytes)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveConnection);
		}, 1);
	};

	return {
		async directSend(data) {
			if (stopStarted || !isSenderValid()) return;
			activeDirectSends++;
			try {
				const chunk = convertToUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err; throw err;
			} finally { activeDirectSends--; markSendComplete(); }
		},
		async send(data) {
			if (stopStarted || !isSenderValid()) return;
			activeSends++;
			try {
				const chunk = convertToUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) { await flush(); continue; }
					grain.store({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err; throw err;
			} finally { activeSends--; markSendComplete(); }
		},
		flush,
		async stopAndFlush() {
			if (stopStarted) {
				await waitActiveSends();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopStarted = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitActiveSends();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const byobReadMaxLimit = 64 * 1024;
	const isConnectionValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownlinkGrainSender(webSocket, header, isConnectionValid);
	header = null;
	const downlinkController = { stopAndFlush: () => downlinkSender.stopAndFlush() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!isConnectionValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
				} else {
					await downlinkSender.send(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(byobReadMaxLimit);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, byobReadMaxLimit));
				if (!isConnectionValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainPacketBytes) {
					await downlinkSender.flush();
					await downlinkSender.directSend(value);
					readBuffer = new ArrayBuffer(byobReadMaxLimit);
				} else {
					await downlinkSender.send(value.slice());
					readBuffer = value.buffer.byteLength >= byobReadMaxLimit ? value.buffer : new ArrayBuffer(byobReadMaxLimit);
				}
			}
		}
		if (isConnectionValid()) await downlinkSender.flush();
	} catch (err) { readError = err }
	finally {
		if (isConnectionValid() && webSocket.readyState === WebSocket.OPEN) {
			try { await downlinkSender.stopAndFlush() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === downlinkController) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && isConnectionValid()) {
		try {
			await retryFunc(); return;
		} catch (err) { readError ||= err; }
	}
	if (!isConnectionValid()) return;
	closeSocketQuietly(webSocket);
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) { return false; }
}

const dohCache = {};
const dohCacheMaxItems = 256;
const dohRecordTypeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function queryDoH(domain, recordType, dohResolverService = "https://cloudflare-dns.com/dns-query") {
	const normalizedDomain = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
	const normalizedRecordType = String(recordType || '').trim().toUpperCase();
	const cacheKey = `${normalizedDomain}:${normalizedRecordType}`;
	const qtype = dohRecordTypeMap[normalizedRecordType] || 1;
	const currentTimestamp = Date.now();
	const existingCacheItem = dohCache[cacheKey];
	if (existingCacheItem && currentTimestamp < existingCacheItem.expiryTime) {
		return existingCacheItem.data.map(data => ({ type: qtype, data }));
	}
	try {
		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		const qname = encodeDomain(normalizedDomain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); 
		qview.setUint16(2, 0x0100); 
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);

		const response = await fetch(dohResolverService, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) return [];

		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);

		const parseDomain = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseDomain(offset);
			offset = /** @type {number} */ (end) + 4;
		}

		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseDomain(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				const [cname] = parseDomain(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		
		const relevantRecords = answers.filter(answer => answer.type === qtype);
		const minTTL = relevantRecords.length > 0 ? Math.min(...relevantRecords.map(a => a.TTL)) : 0;
		const cacheTTL = Math.max(minTTL, 5 * 60);
		const cacheExpiryTime = Date.now() + cacheTTL * 1000;
		const cacheData = relevantRecords.map(answer => answer.data);
		if (cacheData.length > 0 || answers.length === 0) {
			if (Object.keys(dohCache).length >= dohCacheMaxItems) {
				const cleanupTimestamp = Date.now();
				for (const [cacheEntryKey, cacheEntry] of Object.entries(dohCache)) {
					if (cleanupTimestamp >= cacheEntry.expiryTime) delete dohCache[cacheEntryKey];
				}
				if (Object.keys(dohCache).length >= dohCacheMaxItems) {
					delete dohCache[Object.keys(dohCache)[0]];
				}
			}
			dohCache[cacheKey] = { data: cacheData, expiryTime: cacheExpiryTime };
		}
		return answers;
	} catch (error) { return []; }
}

async function parseAddressPort(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function parseAddressPortString(str) {
		let address = str, port = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			address = parts[0] + ']';
			port = parseInt(parts[1], 10) || port;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			address = str.slice(0, colonIndex);
			port = parseInt(str.slice(colonIndex + 1), 10) || port;
		}
		return [address, port];
	}

	function parseTxtProxyRecord(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => parseAddressPortString(prefix));
	}

	const proxyIpArray = await parseToArray(proxyIP);
	let allProxyArray = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	for (const singleProxyIP of proxyIpArray) {
		let [address, port] = parseAddressPortString(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) port = parseInt(tpMatch[1], 10);
		}

		if (ipv4Regex.test(address) || ipv6Regex.test(address)) {
			allProxyArray.push([address, port]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			queryDoH(address, 'TXT'),
			queryDoH(address, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = parseTxtProxyRecord(txtData);
		if (txtAddresses.length > 0) {
			allProxyArray.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			allProxyArray.push(...ipv4List.map(ip => [ip, port]));
			continue;
		}

		const aaaaRecords = await queryDoH(address, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			allProxyArray.push(...ipv6List.map(ip => [ip, port]));
		} else {
			allProxyArray.push([address, port]);
		}
	}
	const sortedArray = allProxyArray.sort((a, b) => a[0].localeCompare(b[0]));
	const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
	let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	const shuffledArray = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const parseResult = shuffledArray.slice(0, 8);
	return parseResult;
}

// ==============================================================================
// WEBSOCKET & TCP DATA FORWARDING KERNEL
// ==============================================================================

function isValidWSEarlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && uuidByteMatch(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;
	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWSEarlyData(header, token) {
	if (!header) return null;
	if (header.length > wsEarlyDataMaxHeadLen) throw new Error('early data is too large');
	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try { bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' }); } catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try { binaryString = atob(normalized); } catch (_) { return null; }
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}
	if (bytes.byteLength > wsEarlyDataMaxBytes) throw new Error('early data is too large');
	return isValidWSEarlyData(bytes, token) ? bytes : null;
}

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = convertToUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}
	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };
	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command" };
	const isUDP = cmd === 3;
	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1:
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3:
			if (data.byteLength < addressIndex + 1) return { hasError: true };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true };
			address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4:
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default: return { hasError: true, message: `invalid addressType is ${atype}` };
	}
	if (!address) return { hasError: true };
	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return { hasError: false, addressType: atype, port: portRemote, hostname: address, isUDP, rawClientData: data.subarray(portIndex + 4) };
}

function parseVlessRequest(chunk, token) {
	const data = convertToUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!uuidByteMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default: return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

async function connectTrojanProxy(firstPacketData, tcpConnection, trojanProxyTarget) {
	if (!trojanProxyTarget) throw new Error('trojan fallback is not configured');
	const socket = tcpConnection({ hostname: stripIPv6Brackets(trojanProxyTarget.hostname), port: trojanProxyTarget.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (getValidDataLength(firstPacketData) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(convertToUint8Array(firstPacketData));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

async function forwardTrojanUdpProxyData(chunk, webSocket, context, request) {
	const data = convertToUint8Array(chunk);
	if (!context.proxySocket) {
		const tcpConnection = createRequestTcpConnector(request);
		const socket = await connectTrojanProxy(data, tcpConnection, context.proxyAddress);
		context.proxySocket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = context.proxySocket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

async function forwardTrojanUdpData(chunk, webSocket, context, request) {
	const currentChunk = convertToUint8Array(chunk);
	if (context?.proxyAddress) return forwardTrojanUdpProxyData(currentChunk, webSocket, context, request);
	const cacheChunk = context?.cache instanceof Uint8Array ? context.cache : new Uint8Array(0);
	const input = cacheChunk.byteLength ? mergeByteData(cacheChunk, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addressPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDnsQuery = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDnsQuery = new Uint8Array(payload.byteLength + 2);
			tcpDnsQuery[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDnsQuery[1] = payload.byteLength & 0xff;
			tcpDnsQuery.set(payload, 2);
		}

		const dnsResponseContext = { cache: new Uint8Array(0) };
		await forwardDataUdp(tcpDnsQuery, webSocket, null, request, (dnsRespChunk) => {
			const currentRespChunk = convertToUint8Array(dnsRespChunk);
			const respInput = dnsResponseContext.cache.byteLength ? mergeByteData(dnsResponseContext.cache, currentRespChunk) : currentRespChunk;
			const respFrameList = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= respInput.byteLength) {
				const dnsLen = (respInput[responseCursor] << 8) | respInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > respInput.byteLength) break;
				const dnsPayload = respInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addressPortHeader.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addressPortHeader, 0);
				frame[addressPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addressPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addressPortHeader.byteLength + 2] = 0x0d;
				frame[addressPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addressPortHeader.byteLength + 4);
				respFrameList.push(frame);
				responseCursor = dnsEnd;
			}
			dnsResponseContext.cache = respInput.slice(responseCursor);
			return respFrameList.length ? respFrameList : new Uint8Array(0);
		});
	}
	if (context) context.cache = input.slice(cursor);
}

async function forwardDataUdp(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = convertToUint8Array(udpChunk);
	try {
		const tcpConnection = createRequestTcpConnector(request);
		const tcpSocket = tcpConnection({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const originalResp = convertToUint8Array(chunk);
				const wrapResult = responseWrapper ? await responseWrapper(originalResp) : originalResp;
				const sendFragmentList = Array.isArray(wrapResult) ? wrapResult : [wrapResult];
				if (!sendFragmentList.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of sendFragmentList) {
					const forwardResp = convertToUint8Array(fragment);
					if (!forwardResp.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + forwardResp.byteLength);
						response.set(vlessHeader, 0);
						response.set(forwardResp, vlessHeader.length);
						await webSocketSendAndWait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await webSocketSendAndWait(webSocket, forwardResp);
					}
				}
			},
		}));
	} catch (error) { }
}

async function forwardDataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, proxyContext = {}, allowTrojanProxy = false, trojanProxyFirstPacketData = null) {
	const ctxProxyIP = proxyContext.proxyIP || '';
	const ctxProxyFallback = proxyContext.proxyFallback !== undefined ? proxyContext.proxyFallback : true;
	let proxyArrayIndex = 0;
	const connectionTimeoutMs = 1000;
	let hasSentFirstPacketViaProxy = false;
	const tcpConnection = createRequestTcpConnector(request);
	const useTrojanProxy = allowTrojanProxy && (proxyContext.trojanProxyAddress || null);
	const trojanProxyTarget = useTrojanProxy ? proxyContext.trojanProxyAddress : null;
	const trojanProxyHandshakeData = useTrojanProxy ? extractTrojanProxyHandshakeData(trojanProxyFirstPacketData, rawData) : null;
	
	let pendingResponseHeader = respHeader;
	const takeOutResponseHeader = () => {
		const header = pendingResponseHeader;
		pendingResponseHeader = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const installCurrentConnection = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const isConnectionStillValid = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		connectStreams(socket, ws, takeOutResponseHeader, retryFunc, isConnectionStillValid, remoteConnWrapper).catch(err => {
			if (!isConnectionStillValid()) return;
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitForConnectionEstablishment(remoteSock, timeoutMs = connectionTimeoutMs) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('Connection timeout')), timeoutMs))
		]);
	}

	async function openTcpConnection(address, port) {
		const remoteSock = tcpConnection({ hostname: address, port });
		try {
			await waitForConnectionEstablishment(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function writeFirstPacket(remoteSock, data) {
		if (getValidDataLength(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(convertToUint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function concurrentOpenCandidateConnections(candidateList) {
		if (candidateList.length === 1) {
			const candidate = candidateList[0];
			return { socket: await openTcpConnection(candidate.hostname, candidate.port), candidate: candidate };
		}
		const attempts = candidateList.map(candidate => openTcpConnection(candidate.hostname, candidate.port).then(socket => ({ socket, candidate })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function buildPreloadRaceCandidateList(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		const [aRecords, aaaaRecords] = await Promise.all([
			queryDoH(address, 'A'),
			queryDoH(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const dialLimit = Math.max(1, tcpConcurrentDials | 0);
		const ipList = ipv4List.length >= dialLimit
			? ipv4List.slice(0, dialLimit)
			: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
		
		if (ipList.length === 0) return null;
		return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	function isIPv4(value) {
		const parts = String(value || '').split('.');
		return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
	}

	async function connectDirect(address, port, data = null, enablePreload = false) {
		const preloadCandidateList = enablePreload ? await buildPreloadRaceCandidateList(address, port) : null;
		const candidateList = preloadCandidateList || Array.from({ length: tcpConcurrentDials }, (_, attempt) => ({ hostname: address, port, attempt }));
		let socket = null;
		try {
			const connectionResult = await concurrentOpenCandidateConnections(candidateList);
			socket = connectionResult.socket;
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allProxyArray = null, enableProxyFallback = true) {
		if (allProxyArray && allProxyArray.length > 0) {
			const actualConcurrentCount = Math.max(1, Math.floor(Number(proxyConcurrentDials) || 1));
			for (let i = 0; i < allProxyArray.length; i += actualConcurrentCount) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrentCount && i + j < allProxyArray.length; j++) {
					const index = (proxyArrayIndex + i + j) % allProxyArray.length;
					const [proxyAddress, proxyPort] = allProxyArray[index];
					candidateList.push({ hostname: proxyAddress, port: proxyPort, index: index });
				}
				let socket = null, candidate = null;
				try {
					const connectionResult = await concurrentOpenCandidateConnections(candidateList);
					socket = connectionResult.socket;
					candidate = connectionResult.candidate;
					await writeFirstPacket(socket, data);
					proxyArrayIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
				}
			}
		}

		if (enableProxyFallback) return connectDirect(address, port, data, false);
		else throw new Error('[Proxy Connection] All reverse proxy connections failed.');
	}

	async function connectToProxy(allowSendFirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentConnectionGeneration, downlinkDrain } = startTCPGeneration(remoteConnWrapper);

		let willSendFirstPacket = false, currentFirstPacketData = null;
		if (useTrojanProxy) {
			if (allowSendFirstPacket && !hasSentFirstPacketViaProxy && getValidDataLength(trojanProxyFirstPacketData) > 0) {
				currentFirstPacketData = trojanProxyFirstPacketData;
				willSendFirstPacket = getValidDataLength(rawData) > 0;
			} else {
				currentFirstPacketData = trojanProxyHandshakeData;
			}
		} else {
			willSendFirstPacket = allowSendFirstPacket && !hasSentFirstPacketViaProxy && getValidDataLength(rawData) > 0;
			currentFirstPacketData = willSendFirstPacket ? rawData : null;
		}

		const currentConnectionTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanProxy) {
					newSocket = await connectTrojanProxy(currentFirstPacketData, tcpConnection, trojanProxyTarget);
				} else {
					const allProxyArray = await parseAddressPort(ctxProxyIP, host, yourUUID);
					newSocket = await connectProxyIP(host, portNum, currentFirstPacketData, allProxyArray, ctxProxyFallback);
				}
				await installCurrentConnection(newSocket, currentConnectionGeneration, downlinkDrain);
				if (willSendFirstPacket) hasSentFirstPacketViaProxy = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === currentConnectionGeneration) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = currentConnectionTask;
		try {
			await currentConnectionTask;
		} finally {
			if (remoteConnWrapper.connectingPromise === currentConnectionTask) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	
	remoteConnWrapper.retryConnect = async () => connectToProxy(!hasSentFirstPacketViaProxy);

	let directGeneration = remoteConnWrapper.generation;
	try {
		const generationConn = startTCPGeneration(remoteConnWrapper);
		directGeneration = generationConn.generation;
		const initialSocket = await connectDirect(host, portNum, rawData, true);
		await installCurrentConnection(initialSocket, directGeneration, generationConn.downlinkDrain, async () => {
			if (remoteConnWrapper.generation !== directGeneration || remoteConnWrapper.socket !== initialSocket) return;
			await connectToProxy();
		});
	} catch (err) {
		if (remoteConnWrapper.generation !== directGeneration) throw err;
		if (ws.readyState !== WebSocket.OPEN) throw err;
		await connectToProxy();
	}
}

async function handleWSRequest(request, yourUUID, url, proxyContext = {}) {
	const wsPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wsPair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidateRemoteConnection = () => invalidateTCPGeneration(remoteConnWrapper);
	
	let isDnsQuery = false;
	let checkIsTrojan = null;
	const trojanUdpContext = { cache: new Uint8Array(0), proxyAddress: proxyContext.trojanProxyAddress };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	
	let wsUplinkWriteQueue = null;
	let wsExplicitTransmissionChain = Promise.resolve();
	let wsExplicitTransmissionStopReceiving = false, wsExplicitTransmissionFailed = false, wsExplicitTransmissionFinalized = false;
	let wsExplicitQueueBytes = 0, wsExplicitQueueItems = 0;
	let checkProtocolType = null, currentWriteSocket = null, remoteWriter = null;
	let wsLocalSpeedTestMode = false, wsLocalSpeedTestResponseSocket = null;
	let wsLocalSpeedTestRequestCache = new Uint8Array(0);
	let wsLocalSpeedTestFirstPacketRespHeader = null;
	const wsLocalSpeedTestRequestMax = 64 * 1024;

	const sendWSLocalSpeedTestResponse = async () => {
		if (!wsLocalSpeedTestResponseSocket) return;
		const respHeader = wsLocalSpeedTestFirstPacketRespHeader;
		wsLocalSpeedTestFirstPacketRespHeader = null;
		await webSocketSendAndWait(wsLocalSpeedTestResponseSocket, buildWSLocal204Response(respHeader));
	};

	const findHttpRequestHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const handleWSLocalSpeedTestData = async (data) => {
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return;
		if (wsLocalSpeedTestRequestCache.byteLength + chunk.byteLength > wsLocalSpeedTestRequestMax) throw new Error('WS local speed-test request is too large');
		wsLocalSpeedTestRequestCache = mergeByteData(wsLocalSpeedTestRequestCache, chunk);

		while (wsLocalSpeedTestRequestCache.byteLength) {
			const headerEnd = findHttpRequestHeaderEnd(wsLocalSpeedTestRequestCache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(wsLocalSpeedTestRequestCache.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > wsLocalSpeedTestRequestMax) throw new Error('WS local speed-test request body is too large');
			if (wsLocalSpeedTestRequestCache.byteLength < requestLength) return;
			wsLocalSpeedTestRequestCache = wsLocalSpeedTestRequestCache.slice(requestLength);
			await sendWSLocalSpeedTestResponse();
		}
	};

	const enableWSLocalSpeedTestMode = async (responseSocket, respHeader = null, firstRequestData = null) => {
		wsLocalSpeedTestMode = true;
		wsLocalSpeedTestResponseSocket = responseSocket;
		wsLocalSpeedTestRequestCache = new Uint8Array(0);
		wsLocalSpeedTestFirstPacketRespHeader = respHeader;
		if (getValidDataLength(firstRequestData) > 0) await handleWSLocalSpeedTestData(firstRequestData);
	};

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const uplinkWriteQueue = wsUplinkWriteQueue = createUplinkWriteQueue({
		getWriter: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		},
		getConnectionTask: () => remoteConnWrapper.connectingPromise,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConnection: err => handleWSExplicitTransmissionError(err),
		queueName: 'WS_Uplink'
	});

	const writeToRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.write(chunk, allowRetry);
	};

	const handleWSInboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (checkIsTrojan) return await forwardTrojanUdpData(chunk, serverSock, trojanUdpContext, request);
			return await forwardDataUdp(chunk, serverSock, null, request);
		}
		if (wsLocalSpeedTestMode) {
			await handleWSLocalSpeedTestData(chunk);
			return;
		}
		if (await writeToRemote(chunk)) return;

		if (checkProtocolType === null) {
			currentChunkBytes = currentChunkBytes || convertToUint8Array(chunk);
			const bytes = currentChunkBytes;
			checkProtocolType = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
			checkIsTrojan = checkProtocolType === 'trojan';
		}

		if (await writeToRemote(chunk)) return;
		if (checkProtocolType === 'trojan') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = parseResult;
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUdpContext.targetHost = hostname;
				trojanUdpContext.targetPort = port;
				if (trojanUdpContext.proxyAddress) return forwardTrojanUdpData(currentChunkBytes || convertToUint8Array(chunk), serverSock, trojanUdpContext, request);
				if (getValidDataLength(rawClientData) > 0) return forwardTrojanUdpData(rawClientData, serverSock, trojanUdpContext, request);
				return;
			}
			await forwardDataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, proxyContext, true, currentChunkBytes || convertToUint8Array(chunk));
		} else {
			checkIsTrojan = false;
			currentChunkBytes = currentChunkBytes || convertToUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVlessRequest(bytes, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
			const { port, hostname, version, isUDP, rawClientData } = parseResult;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && proxyContext.proxyType === null) {
				await enableWSLocalSpeedTestMode(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (checkIsTrojan) return forwardTrojanUdpData(rawData, serverSock, trojanUdpContext, request);
				return forwardDataUdp(rawData, serverSock, respHeader, request);
			}
			await forwardDataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, proxyContext);
		}
	};

	const handleWSExplicitTransmissionError = (err) => {
		if (wsExplicitTransmissionFailed) return;
		wsExplicitTransmissionFailed = true;
		wsExplicitTransmissionStopReceiving = true;
		wsExplicitQueueBytes = 0;
		wsExplicitQueueItems = 0;
		uplinkWriteQueue.clearQueue();
		releaseRemoteWriter();
		invalidateRemoteConnection();
		try { trojanUdpContext.proxySocket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const appendWSExplicitTransmissionTask = (task) => {
		wsExplicitTransmissionChain = wsExplicitTransmissionChain.then(task).catch(handleWSExplicitTransmissionError);
		return wsExplicitTransmissionChain;
	};

	const enqueueWSExplicitTransmission = (data) => {
		if (wsExplicitTransmissionStopReceiving || wsExplicitTransmissionFailed) return;
		const chunkSize = Math.max(0, getValidDataLength(data));
		const nextBytes = wsExplicitQueueBytes + chunkSize;
		const nextItems = wsExplicitQueueItems + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxItems) {
			handleWSExplicitTransmissionError(new Error(`[WS Explicit Transmission] Queue overflow: ${nextBytes}B/${nextItems}`));
			return;
		}
		wsExplicitQueueBytes = nextBytes;
		wsExplicitQueueItems = nextItems;
		appendWSExplicitTransmissionTask(async () => {
			wsExplicitQueueBytes = Math.max(0, wsExplicitQueueBytes - chunkSize);
			wsExplicitQueueItems = Math.max(0, wsExplicitQueueItems - 1);
			if (wsExplicitTransmissionFailed) return;
			await handleWSInboundData(data);
		});
	};

	const finalizeWSExplicitTransmission = () => {
		if (wsExplicitTransmissionFinalized) return;
		wsExplicitTransmissionFinalized = true;
		wsExplicitTransmissionStopReceiving = true;
		appendWSExplicitTransmissionTask(async () => {
			if (wsExplicitTransmissionFailed) return;
			await uplinkWriteQueue.waitEmpty();
			releaseRemoteWriter();
			invalidateRemoteConnection();
			try { trojanUdpContext.proxySocket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		enqueueWSExplicitTransmission(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		finalizeWSExplicitTransmission();
	});
	serverSock.addEventListener('error', (err) => {
		handleWSExplicitTransmissionError(err);
	});

	if (earlyDataHeader) {
		try {
			const bytes = decodeWSEarlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) enqueueWSExplicitTransmission(bytes.buffer);
		} catch (error) {
			handleWSExplicitTransmissionError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}
