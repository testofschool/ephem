import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { CiphertextStore, StoreError } from '../../zero/store.mjs';
import { createRelay, gateEcho, MAX_HTTP_BODY, secureHostMemory } from '../../zero/relay.mjs';
import { seal, unseal } from '../../zero/client.mjs';

const testOnlyPreflight = async () => {};
const echo = async bytes => Buffer.from(bytes);

async function fixture(t, config = {}) {
  const relay = await createRelay({ testOnlyPreflight, testOnlyGateBridge: echo, ...config });
  t.after(() => relay.close());
  const address = await relay.listen();
  return { ...relay, port: address.port };
}

async function exchange(port, path, body, { method = 'POST', headers = {} } = {}) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
  return await new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path, method, agent: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': bytes.length,
        Connection: 'close', ...headers } }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode,
        headers: response.headers, bytes: Buffer.concat(chunks) }));
    });
    request.on('error', reject); request.end(bytes);
  });
}

async function health(port) {
  return await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/health', agent: false }, response => {
      const chunks = []; response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks))));
    }).on('error', reject);
  });
}

test('RAM store owns ciphertext copy, claims once, and expires exactly at deadline', () => {
  let now = 100;
  const store = new CiphertextStore({ ttlMs: 30, now: () => now });
  try {
    const original = Buffer.from('ciphertext');
    const receipt = store.put(original);
    original.fill(0);
    assert.match(receipt.token, /^[0-9a-f]{64}$/);
    assert.deepEqual(store.stats(), { objects: 1, bytes: 10 });
    const snapshot = store.snapshotCiphertexts();
    assert.equal(snapshot[0].toString(), 'ciphertext');
    snapshot[0].fill(0);
    now = 129;
    const claimed = store.take(receipt.token);
    assert.equal(claimed.toString(), 'ciphertext'); claimed.fill(0);
    assert.equal(store.take(receipt.token), undefined);
    const next = store.put(Buffer.from('next'));
    now = 159;
    assert.equal(store.take(next.token), undefined);
    assert.deepEqual(store.stats(), { objects: 0, bytes: 0 });
  } finally { store.close(); }
});

test('RAM store enforces individual, slot, and aggregate limits', () => {
  const store = new CiphertextStore({ maxSlots: 2, maxEnvelopeBytes: 5, maxTotalBytes: 8 });
  try {
    assert.throws(() => store.put(Buffer.alloc(6)), error => error instanceof StoreError && error.code === 'size');
    store.put(Buffer.alloc(5));
    assert.throws(() => store.put(Buffer.alloc(4)), /full/);
    store.put(Buffer.alloc(3));
    assert.throws(() => store.put(Buffer.alloc(1)), /full/);
    store.close();
    assert.deepEqual(store.stats(), { objects: 0, bytes: 0 });
    assert.throws(() => store.put(Buffer.alloc(1)), /closed/);
  } finally { store.close(); }
});

test('RAM store rejects unsafe configuration and TTL over 60 seconds', () => {
  for (const options of [{ ttlMs: 60_001 }, { ttlMs: 0 }, { ttlMs: NaN }, { maxSlots: 0 },
    { maxEnvelopeBytes: 1024 * 1024 + 1 }, { maxTotalBytes: 8 * 1024 * 1024 + 1 }]) {
    assert.throws(() => new CiphertextStore(options));
  }
});

test('client encrypts and decrypts; relay and worker receive ciphertext only', async t => {
  const plaintext = Buffer.from('a unique private payload stays on the client');
  const sealed = seal(plaintext);
  let seen;
  const relay = await fixture(t, { testOnlyGateBridge: async canonical => {
    seen = Buffer.from(canonical); return Buffer.from(canonical);
  } });
  const uploaded = await exchange(relay.port, '/v1/objects', sealed.envelope);
  assert.equal(uploaded.status, 201);
  assert.deepEqual(seen, sealed.envelope);
  assert.equal(seen.includes(plaintext), false);
  assert.equal(seen.includes(Buffer.from(sealed.key.key)), false);
  const snapshot = relay.store.snapshotCiphertexts();
  assert.deepEqual(snapshot, [sealed.envelope]);
  assert.equal(snapshot[0].includes(plaintext), false);
  assert.equal(snapshot[0].includes(Buffer.from(sealed.key.key)), false);
  const receipt = JSON.parse(uploaded.bytes);
  assert.deepEqual(Object.keys(receipt), ['token', 'expiresInMs']);
  const taken = await exchange(relay.port, '/v1/take', { token: receipt.token });
  assert.equal(taken.status, 200);
  assert.equal(taken.headers['cache-control'], 'no-store');
  assert.deepEqual(unseal(taken.bytes, sealed.key), plaintext);
  assert.equal((await exchange(relay.port, '/v1/take', { token: receipt.token })).status, 404);
  assert.deepEqual(await health(relay.port), { status: 'ok', objects: 0, bytes: 0 });
});

test('simultaneous takes yield exactly one successful claim', async t => {
  const relay = await fixture(t);
  const sealed = seal(Buffer.from('one recipient'));
  const { token } = JSON.parse((await exchange(relay.port, '/v1/objects', sealed.envelope)).bytes);
  const results = await Promise.all(Array.from({ length: 16 }, () => exchange(relay.port, '/v1/take', { token })));
  assert.equal(results.filter(result => result.status === 200).length, 1);
  assert.equal(results.filter(result => result.status === 404).length, 15);
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('a failed take response still consumes the object', async t => {
  const relay = await fixture(t);
  const sealed = seal(Buffer.from('at most once'));
  const { token } = JSON.parse((await exchange(relay.port, '/v1/objects', sealed.envelope)).bytes);
  // Force the network output to fail at the write boundary, after claim/delete.
  const failResponse = (request, response) => {
    if (request.url === '/v1/take') {
      response.end = () => { response.destroy(); return response; };
    }
  };
  relay.server.prependListener('request', failResponse);
  await assert.rejects(exchange(relay.port, '/v1/take', { token }));
  relay.server.removeListener('request', failResponse);
  assert.equal((await exchange(relay.port, '/v1/take', { token })).status, 404);
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('expiry removes the encrypted object without a take request', async t => {
  const relay = await fixture(t, { ttlMs: 25 });
  const sealed = seal(Buffer.from('short lived'));
  const receipt = JSON.parse((await exchange(relay.port, '/v1/objects', sealed.envelope)).bytes);
  await delay(40);
  assert.equal((await exchange(relay.port, '/v1/take', { token: receipt.token })).status, 404);
  assert.deepEqual(await health(relay.port), { status: 'ok', objects: 0, bytes: 0 });
});

test('gate failure and altered output cannot create a retained object', async t => {
  for (const bridge of [async () => { throw new Error('failure with private detail'); }, async () => Buffer.from('altered')]) {
    const relay = await fixture(t, { testOnlyGateBridge: bridge });
    const uploaded = await exchange(relay.port, '/v1/objects', seal(Buffer.from('private')).envelope);
    assert.equal(uploaded.status, 502);
    assert.deepEqual(JSON.parse(uploaded.bytes), { error: 'gate_rejected' });
    assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
  }
});

test('an envelope with a secret key field is rejected before reaching gate', async t => {
  let calls = 0;
  const relay = await fixture(t, { testOnlyGateBridge: async bytes => { calls++; return Buffer.from(bytes); } });
  const sealed = seal(Buffer.from('private'));
  const malformed = { ...JSON.parse(sealed.envelope), key: sealed.key.key };
  assert.equal((await exchange(relay.port, '/v1/objects', malformed)).status, 400);
  assert.equal(calls, 0);
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('strict envelope framing rejects duplicate keys, whitespace, unknown fields, and invalid JSON', async t => {
  let calls = 0;
  const relay = await fixture(t, { testOnlyGateBridge: async bytes => { calls++; return Buffer.from(bytes); } });
  const sealed = seal(Buffer.from('private')).envelope;
  const data = JSON.parse(sealed);
  const bad = [Buffer.from('{'), Buffer.from('null'), Buffer.from('[]'),
    Buffer.concat([Buffer.from(' '), sealed]),
    Buffer.from(sealed.toString().replace('{', '{"version":1,')),
    Buffer.from(JSON.stringify({ ...data, nonce: 'invalid' })),
    Buffer.from(JSON.stringify({ ...data, unknown: 'anything' })),
    Buffer.from(JSON.stringify({ ...data, ciphertext: '-_' })),
    Buffer.from([0xff, 0xfe])];
  for (const bytes of bad) assert.equal((await exchange(relay.port, '/v1/objects', bytes)).status, 400);
  assert.equal(calls, 0);
});

test('token API refuses URL tokens, extra fields, and noncanonical JSON', async t => {
  const relay = await fixture(t);
  const token = 'a'.repeat(64);
  assert.equal((await exchange(relay.port, `/v1/take?token=${token}`, { token })).status, 404);
  for (const body of [{ token, key: 'no' }, { token: token.toUpperCase() }, {}, { token: 1 },
    Buffer.from(`{ "token":"${token}"}`), Buffer.from(`{"token":"${token}","token":"${token}"}`)]) {
    const result = await exchange(relay.port, '/v1/take', body);
    assert.ok(result.status === 400 || result.status === 413);
  }
  assert.equal((await exchange(relay.port, '/v1/take', { token })).status, 404);
});

test('strict HTTP headers reject credentials, browser origins, and alternate hosts', async t => {
  const relay = await fixture(t);
  const sealed = seal(Buffer.from('private')).envelope;
  for (const headers of [{ Authorization: 'Bearer unwanted' }, { Cookie: 'session=unwanted' },
    { Origin: 'https://attacker.example' }, { Host: 'attacker.example' }, { TE: 'trailers' },
    { 'Content-Type': 'application/json; charset=utf-8' }]) {
    assert.equal((await exchange(relay.port, '/v1/objects', sealed, { headers })).status, 400);
  }
});

test('an oversized declared body is refused before reading or invoking gate', async t => {
  let calls = 0;
  const relay = await fixture(t, { testOnlyGateBridge: async bytes => { calls++; return Buffer.from(bytes); } });
  const result = await exchange(relay.port, '/v1/objects', Buffer.alloc(0), {
    headers: { 'Content-Length': String(MAX_HTTP_BODY + 1) },
  });
  assert.equal(result.status, 413); assert.equal(calls, 0);
});

test('a refused oversized streaming body may receive 413 or a connection reset', async t => {
  let calls = 0;
  const relay = await fixture(t, { testOnlyGateBridge: async bytes => { calls++; return Buffer.from(bytes); } });
  // The server closes without draining attacker-controlled oversized bytes.
  // Operating systems differ on whether the sender observes the 413 or reset.
  const result = await exchange(relay.port, '/v1/objects', Buffer.alloc(MAX_HTTP_BODY + 1)).catch(error => {
    assert.ok(['ECONNRESET', 'EPIPE'].includes(error.code), `unexpected transport error ${error.code}`);
  });
  if (result) assert.equal(result.status, 413);
  assert.equal(calls, 0);
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('maximum supported plaintext remains inside relay wire limit', async t => {
  const relay = await fixture(t);
  const sealed = seal(Buffer.alloc(512 * 1024, 42));
  assert.ok(sealed.envelope.length < MAX_HTTP_BODY);
  const uploaded = await exchange(relay.port, '/v1/objects', sealed.envelope);
  assert.equal(uploaded.status, 201);
  const { token } = JSON.parse(uploaded.bytes);
  const taken = await exchange(relay.port, '/v1/take', { token });
  assert.deepEqual(unseal(taken.bytes, sealed.key), Buffer.alloc(512 * 1024, 42));
});

test('slot and byte budgets return fixed capacity failure', async t => {
  const sealed = seal(Buffer.from('payload')).envelope;
  for (const config of [{ maxSlots: 1 }, { maxTotalBytes: sealed.length + 1 }]) {
    const relay = await fixture(t, config);
    assert.equal((await exchange(relay.port, '/v1/objects', sealed)).status, 201);
    const result = await exchange(relay.port, '/v1/objects', sealed);
    assert.equal(result.status, 503);
    assert.deepEqual(JSON.parse(result.bytes), { error: 'capacity' });
    assert.equal(relay.store.stats().objects, 1);
  }
});

test('in-flight gate jobs are bounded and shutdown cannot retain a late result', async t => {
  let release;
  const started = new Promise(resolve => { release = resolve; });
  let unblock;
  const blocked = new Promise(resolve => { unblock = resolve; });
  const relay = await fixture(t, { maxSlots: 1, testOnlyGateBridge: async bytes => {
    release(); await blocked; return Buffer.from(bytes);
  } });
  const sealed = seal(Buffer.from('pending')).envelope;
  const first = exchange(relay.port, '/v1/objects', sealed).catch(() => undefined);
  await started;
  assert.equal((await exchange(relay.port, '/v1/objects', sealed)).status, 503);
  await relay.close(); unblock(); await first; await delay(1);
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('shutdown clears all retained objects and is idempotent', async t => {
  const relay = await fixture(t);
  assert.equal((await exchange(relay.port, '/v1/objects', seal(Buffer.from('data')).envelope)).status, 201);
  assert.equal(relay.store.stats().objects, 1);
  await relay.close(); await relay.close();
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
  await assert.rejects(relay.listen(), /closed/);
});

test('a colliding port fails without replacing the existing listener', async t => {
  const first = await fixture(t);
  const second = await createRelay({ port: first.port, testOnlyPreflight, testOnlyGateBridge: echo });
  t.after(() => second.close());
  await assert.rejects(second.listen(), error => error.code === 'EADDRINUSE');
  assert.equal((await health(first.port)).status, 'ok');
});

test('the service refuses any non-loopback listener', async () => {
  for (const host of ['0.0.0.0', 'localhost', '::', '192.0.2.10']) {
    await assert.rejects(createRelay({ host, testOnlyPreflight, testOnlyGateBridge: echo }), /loopback/);
  }
});

test('real gate operation requires an explicit pinned root-manifest digest', async () => {
  for (const rootManifestSha256 of [undefined, '', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64)]) {
    await assert.rejects(createRelay({ gateSocket: '/run/unused.sock', rootManifestSha256,
      testOnlyPreflight }), /pinned manifest digest required/);
    await assert.rejects(gateEcho('/run/unused.sock', Buffer.from('ciphertext'), undefined,
      { expectedManifestSha256: rootManifestSha256 }), /pinned manifest digest required/);
  }
});

test('no plaintext, decryption, dump, or debugging route is present', async t => {
  const relay = await fixture(t);
  for (const path of ['/decrypt', '/v1/decrypt', '/debug', '/dump', '/v1/objects/all', '/network']) {
    const result = await exchange(relay.port, path, {});
    assert.equal(result.status, 404);
    assert.deepEqual(JSON.parse(result.bytes), { error: 'not_found' });
  }
});

test('Transfer-Encoding, Expect, Upgrade, and missing length fail closed', async t => {
  const relay = await fixture(t);
  const base = `POST /v1/objects HTTP/1.1\r\nHost: 127.0.0.1:${relay.port}\r\nContent-Type: application/json\r\n`;
  for (const framing of ['Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    'Expect: 100-continue\r\nContent-Length: 2\r\n\r\n{}',
    'Upgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 2\r\n\r\n{}',
    'Trailer: checksum\r\nContent-Length: 2\r\n\r\n{}', '\r\n']) {
    const socket = net.createConnection({ host: '127.0.0.1', port: relay.port });
    await once(socket, 'connect');
    const chunks = []; socket.on('data', chunk => chunks.push(chunk));
    const ended = once(socket, 'close'); socket.write(base + framing); await ended;
    assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1\.1 400 /);
  }
  assert.deepEqual(relay.store.stats(), { objects: 0, bytes: 0 });
});

test('CLI exposes no test bypass and emits only a fixed startup failure', async () => {
  for (const args of [[], ['--test-only-preflight', 'true'], ['--host', '0.0.0.0'], ['--port', '0'],
    ['--gate-socket', '/run/unused.sock']]) {
    const child = spawn(process.execPath, [new URL('../../zero/relay.mjs', import.meta.url).pathname, ...args]);
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
    const [code] = await once(child, 'close');
    assert.equal(code, 1); assert.equal(stdout, ''); assert.equal(stderr, 'relay startup failed\n');
  }
});

test('host preflight fails on non-Linux without a portability bypass', async () => {
  if (process.platform !== 'linux') await assert.rejects(secureHostMemory(), /Linux required/);
});
