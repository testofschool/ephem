import http from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CiphertextStore, StoreError } from './store.mjs';
import { validateEnvelope } from './envelope.mjs';

export const MAX_HTTP_BODY = 900 * 1024;
const TOKEN = /^[0-9a-f]{64}$/;
const MANIFEST_DIGEST = /^[0-9a-f]{64}$/;
const FORBIDDEN_HEADERS = new Set(['transfer-encoding', 'expect', 'upgrade', 'trailer',
  'authorization', 'proxy-authorization', 'cookie', 'origin']);

export async function secureHostMemory() {
  if (process.platform !== 'linux') throw new Error('Linux required');
  const [swaps, pattern, limits] = await Promise.all([
    readFile('/proc/swaps', 'utf8'), readFile('/proc/sys/kernel/core_pattern', 'utf8'),
    readFile('/proc/self/limits', 'utf8'),
  ]);
  const rows = swaps.trim().split(/\r?\n/);
  if (rows.length !== 1 || !rows[0].startsWith('Filename')) throw new Error('swap must be disabled');
  if (!pattern.trim() || pattern.trimStart().startsWith('|')) throw new Error('piped core handler forbidden');
  const core = limits.match(/^Max core file size\s+(\S+)\s+(\S+)\s+bytes\s*$/m);
  if (!core || core[1] !== '0' || core[2] !== '0') throw new Error('core soft and hard limits must be zero');
}

/** Root-owned authority, including every path component. A /run path is usual. */
export async function validateGateSocket(socketPath) {
  if (typeof socketPath !== 'string' || !isAbsolute(socketPath) || resolve(socketPath) !== socketPath ||
    await realpath(socketPath) !== socketPath) throw new Error('canonical gate socket required');
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.uid !== 0 || (socket.mode & 0o077) !== 0) {
    throw new Error('root-owned private gate socket required');
  }
  let directory = dirname(socketPath);
  for (;;) {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== 0 ||
      (metadata.mode & 0o022) !== 0) throw new Error('trusted gate ancestry required');
    if (directory === '/') break;
    directory = dirname(directory);
  }
  return { dev: socket.dev, ino: socket.ino };
}

function uniqueHeaders(rawHeaders) {
  const headers = new Map();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i].toLowerCase();
    if (headers.has(name)) throw new Error('duplicate header');
    headers.set(name, rawHeaders[i + 1]);
  }
  return headers;
}

function sameBytes(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Gate headers come from the trusted supervisor, never from the worker. */
export async function gateEcho(socketPath, canonical, identity,
  { timeoutMs = 3000, signal, expectedManifestSha256 } = {}) {
  if (!MANIFEST_DIGEST.test(expectedManifestSha256 ?? '')) throw new Error('pinned manifest digest required');
  const current = await validateGateSocket(socketPath);
  if (identity && (current.dev !== identity.dev || current.ino !== identity.ino)) {
    throw new Error('gate socket changed');
  }
  const payload = Buffer.concat([Buffer.from('ECHO '), canonical]);
  try {
    return await new Promise((fulfill, reject) => {
      let settled = false;
      let request;
      const chunks = [];
      let received = 0;
      // A socket inactivity timeout alone allows a slow trickle to run forever.
      const deadline = setTimeout(() => {
        request?.destroy(); finish(new Error('gate deadline'));
      }, timeoutMs);
      deadline.unref();
      const finish = (error, bytes) => {
        if (settled) { bytes?.fill(0); return; }
        settled = true;
        clearTimeout(deadline);
        for (const chunk of chunks) chunk.fill(0);
        if (error) reject(new Error('gate rejected'));
        else fulfill(bytes);
      };
      request = http.request({ socketPath, path: '/run', method: 'POST', agent: false,
        maxHeaderSize: 8192, signal, headers: { Host: 'ephem-gate',
          'Content-Type': 'application/octet-stream', 'Content-Length': payload.length,
          Connection: 'close' } }, response => {
        try {
          const headers = uniqueHeaders(response.rawHeaders);
          const workerPid = Number(headers.get('x-ephem-worker-pid'));
          const elapsedMs = Number(headers.get('x-ephem-elapsed-ms'));
          if (response.statusCode !== 200 || headers.get('content-length') !== String(canonical.length) ||
            headers.get('connection')?.toLowerCase() !== 'close' ||
            headers.get('cache-control') !== 'no-store' || headers.has('transfer-encoding') ||
            headers.get('x-ephem-root-manifest-sha256') !== expectedManifestSha256 ||
            !/^[1-9][0-9]*$/.test(headers.get('x-ephem-worker-pid') ?? '') ||
            !Number.isSafeInteger(workerPid) || workerPid <= 1 || workerPid > 2147483647 ||
            !/^[0-9a-f]{64}$/.test(headers.get('x-ephem-output-sha256') ?? '') ||
            !/^\d+(?:\.\d+)?$/.test(headers.get('x-ephem-elapsed-ms') ?? '') ||
            !Number.isFinite(elapsedMs)) {
            throw new Error('untrusted success');
          }
          response.on('data', chunk => {
            received += chunk.length;
            if (received > canonical.length) {
              chunk.fill(0); request.destroy(); finish(new Error('oversized gate output'));
            } else chunks.push(chunk);
          });
          response.on('end', () => {
            const bytes = Buffer.concat(chunks, received);
            const digest = createHash('sha256').update(bytes).digest('hex');
            if (!response.complete || response.rawTrailers.length || !sameBytes(bytes, canonical) ||
              digest !== headers.get('x-ephem-output-sha256')) {
              bytes.fill(0); finish(new Error('gate output mismatch'));
            } else finish(null, bytes);
          });
          response.on('error', error => finish(error));
          response.on('aborted', () => finish(new Error('gate aborted')));
        } catch (error) {
          response.destroy(); request.destroy(); finish(error);
        }
      });
      request.setTimeout(timeoutMs, () => { request.destroy(); finish(new Error('gate timeout')); });
      request.on('error', error => finish(error));
      request.end(payload);
    });
  } finally { payload.fill(0); }
}

function reply(response, status, value, contentType = 'application/json') {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'Content-Type': contentType, 'Content-Length': body.length,
    Connection: 'close', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  response.end(body);
}

async function readBody(request, expected) {
  const chunks = [];
  let length = 0;
  try {
    for await (const chunk of request) {
      length += chunk.length;
      if (length > expected) { chunk.fill(0); throw new Error('body exceeds length'); }
      chunks.push(chunk);
    }
    if (length !== expected || !request.complete || request.rawTrailers.length) throw new Error('bad body');
    return Buffer.concat(chunks, length);
  } finally { for (const chunk of chunks) chunk.fill(0); }
}

function parseJson(bytes) {
  // Fatal UTF-8 avoids silently replacing invalid byte sequences before validation.
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

/** Test injections are deliberately available only to importers, never CLI flags. */
export async function createRelay({ gateSocket, rootManifestSha256, port = 0, host = '127.0.0.1', ttlMs = 30_000,
  maxSlots = 16, maxEnvelopeBytes, maxTotalBytes, testOnlyPreflight, testOnlyGateBridge } = {}) {
  if (host !== '127.0.0.1' || !Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new TypeError('loopback address and valid port required');
  }
  if (testOnlyPreflight !== undefined && typeof testOnlyPreflight !== 'function') throw new TypeError('bad preflight');
  if (testOnlyGateBridge !== undefined && typeof testOnlyGateBridge !== 'function') throw new TypeError('bad gate');
  if ((!testOnlyGateBridge || rootManifestSha256 !== undefined) &&
    !MANIFEST_DIGEST.test(rootManifestSha256 ?? '')) throw new TypeError('pinned manifest digest required');
  await (testOnlyPreflight ?? secureHostMemory)();
  const gateIdentity = testOnlyGateBridge ? undefined : await validateGateSocket(gateSocket);
  const gate = testOnlyGateBridge ?? ((bytes, signal) => gateEcho(gateSocket, bytes, gateIdentity,
    { signal, expectedManifestSha256: rootManifestSha256 }));
  const store = new CiphertextStore({ ttlMs, maxSlots, maxEnvelopeBytes, maxTotalBytes });
  const connections = new Set();
  const heldResponses = new Set();
  const gateRequests = new Set();
  let closing = false;
  let pending = 0;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000,
    keepAliveTimeout: 1, connectionsCheckingInterval: 250 }, async (request, response) => {
    let accepted = false;
    let raw;
    let canonical;
    let gated;
    try {
      if (closing) { reply(response, 503, { error: 'unavailable' }); return; }
      const headers = uniqueHeaders(request.rawHeaders);
      const address = server.address();
      if (request.httpVersion !== '1.1' || headers.get('host') !== `127.0.0.1:${address.port}` ||
        [...headers.keys()].some(header => FORBIDDEN_HEADERS.has(header)) || headers.has('te')) {
        reply(response, 400, { error: 'rejected' }); return;
      }
      if (request.method === 'GET' && request.url === '/health' && !headers.has('content-length')) {
        reply(response, 200, { status: 'ok', ...store.stats() }); return;
      }
      if (request.method !== 'POST' || !['/v1/objects', '/v1/take'].includes(request.url)) {
        reply(response, 404, { error: 'not_found' }); return;
      }
      const textLength = headers.get('content-length') ?? '';
      if (!/^(?:0|[1-9][0-9]*)$/.test(textLength) || headers.get('content-type') !== 'application/json') {
        reply(response, 400, { error: 'rejected' }); return;
      }
      const length = Number(textLength);
      if (!Number.isSafeInteger(length) || length < 1 || length > MAX_HTTP_BODY ||
        (request.url === '/v1/take' && length > 80)) {
        reply(response, 413, { error: 'size' }); return;
      }
      if (pending >= maxSlots) { reply(response, 503, { error: 'busy' }); return; }
      pending += 1; accepted = true;
      raw = await readBody(request, length);
      const value = parseJson(raw);
      if (request.url === '/v1/take') {
        if (!value || typeof value !== 'object' || Array.isArray(value) ||
          Object.keys(value).length !== 1 || !TOKEN.test(value.token ?? '') ||
          raw.toString('utf8') !== JSON.stringify({ token: value.token })) throw new Error('bad token');
        const ciphertext = store.take(value.token);
        if (!ciphertext) { reply(response, 404, { error: 'not_found' }); return; }
        // The entry was already removed. Even a failed network write consumes it.
        heldResponses.add(ciphertext);
        const clear = () => { ciphertext.fill(0); heldResponses.delete(ciphertext); };
        response.once('finish', clear);
        response.once('close', clear);
        response.once('error', clear);
        reply(response, 200, ciphertext);
        return;
      }
      canonical = validateEnvelope(value);
      if (!Buffer.isBuffer(canonical) || !sameBytes(canonical, raw)) throw new Error('noncanonical envelope');
      const controller = new AbortController();
      gateRequests.add(controller);
      try { gated = await gate(canonical, controller.signal); }
      catch { reply(response, 502, { error: 'gate_rejected' }); return; }
      finally { gateRequests.delete(controller); }
      if (!Buffer.isBuffer(gated) || !sameBytes(gated, canonical)) {
        reply(response, 502, { error: 'gate_rejected' }); return;
      }
      if (closing || response.destroyed) return;
      try { reply(response, 201, store.put(gated)); }
      catch (error) {
        if (error instanceof StoreError) reply(response, 503, { error: 'capacity' });
        else throw error;
      }
    } catch {
      if (!response.headersSent && !response.destroyed) reply(response, 400, { error: 'rejected' });
      else response.destroy();
    } finally {
      raw?.fill(0); canonical?.fill(0); gated?.fill?.(0);
      if (accepted) pending -= 1;
    }
  });
  server.maxRequestsPerSocket = 1;
  server.maxConnections = 32;
  const rejectSocket = socket => {
    if (socket.destroyed || !socket.writable) return;
    socket.once('error', () => socket.destroy());
    socket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  };
  server.on('clientError', (_error, socket) => rejectSocket(socket));
  server.on('upgrade', (_request, socket) => rejectSocket(socket));
  server.on('connect', (_request, socket) => rejectSocket(socket));
  server.on('checkContinue', (_request, response) => reply(response, 400, { error: 'rejected' }));
  server.on('checkExpectation', (_request, response) => reply(response, 400, { error: 'rejected' }));
  server.on('connection', socket => { connections.add(socket); socket.once('close', () => connections.delete(socket)); });
  let closePromise;
  return { server, store,
    listen: () => new Promise((fulfill, reject) => {
      if (closing) { reject(new Error('relay closed')); return; }
      const fail = error => { server.off('listening', listening); reject(error); };
      const listening = () => { server.off('error', fail); fulfill(server.address()); };
      server.once('error', fail); server.once('listening', listening);
      server.listen({ host, port, exclusive: true });
    }),
    close: () => {
      if (closePromise) return closePromise;
      closing = true;
      for (const controller of gateRequests) controller.abort();
      store.close();
      for (const bytes of heldResponses) bytes.fill(0);
      heldResponses.clear();
      closePromise = new Promise(resolveClose => {
        server.close(() => resolveClose());
        for (const socket of connections) socket.destroy();
      });
      return closePromise;
    },
  };
}

async function main() {
  const options = {};
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i += 2) {
    const key = { '--gate-socket': 'gateSocket', '--root-manifest-sha256': 'rootManifestSha256',
      '--port': 'port', '--ttl-ms': 'ttlMs' }[args[i]];
    if (!key || args[i + 1] === undefined || Object.hasOwn(options, key)) throw new Error('invalid arguments');
    const value = args[i + 1];
    const numeric = key === 'port' || key === 'ttlMs';
    if (numeric && !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error('invalid number');
    options[key] = numeric ? Number(value) : value;
  }
  if (!options.gateSocket || !options.rootManifestSha256) throw new Error('gate socket and manifest digest required');
  const relay = await createRelay(options);
  try {
    const address = await relay.listen();
    process.stdout.write(`${JSON.stringify({ event: 'listening', host: address.address, port: address.port })}\n`);
    const shutdown = async () => { await relay.close(); };
    process.once('SIGTERM', shutdown); process.once('SIGINT', shutdown);
  } catch (error) { await relay.close(); throw error; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => { process.stderr.write('relay startup failed\n'); process.exitCode = 1; });
}
