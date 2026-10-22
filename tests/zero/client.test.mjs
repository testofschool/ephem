import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, webcrypto} from 'node:crypto';
import {mkdtempSync, writeFileSync, readFileSync, statSync, chmodSync, existsSync, rmSync, symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {seal, unseal} from '../../zero/client.mjs';
import {MAX_PLAINTEXT, validateEnvelope, associatedData} from '../../zero/envelope.mjs';

test('empty, binary and maximum-sized data roundtrip with client-only key', () => {
  for (const input of [Buffer.alloc(0), Buffer.from([0, 255, 1, 0]), randomBytes(MAX_PLAINTEXT)]) {
    const record = seal(input);
    assert.deepEqual(unseal(record.envelope, record.key), input);
    assert.equal(Object.hasOwn(JSON.parse(record.envelope), 'key'), false);
    assert.equal(record.envelope.includes(Buffer.from(record.key.key)), false);
  }
  assert.throws(() => seal(Buffer.alloc(MAX_PLAINTEXT + 1)));
});

test('separate WebCrypto interface authenticates actual AES-256-GCM envelope', async () => {
  const input = randomBytes(117);
  const sealed = seal(input); const env = JSON.parse(sealed.envelope);
  const key = await webcrypto.subtle.importKey('raw', Buffer.from(sealed.key.key, 'base64'), 'AES-GCM', false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt({name: 'AES-GCM', iv: Buffer.from(env.nonce, 'base64'),
    additionalData: associatedData(env.id), tagLength: 128}, key,
  Buffer.concat([Buffer.from(env.ciphertext, 'base64'), Buffer.from(env.tag, 'base64')]));
  assert.deepEqual(Buffer.from(plain), input);
});

test('wrong key and authenticated field tampering never produce plaintext', () => {
  const original = seal(Buffer.from('synthetic data'));
  for (const field of ['nonce', 'ciphertext', 'tag']) {
    const env = JSON.parse(original.envelope);
    const changed = Buffer.from(env[field], 'base64'); changed[0] ^= 1;
    env[field] = changed.toString('base64');
    assert.throws(() => unseal(validateEnvelope(env), original.key));
  }
  assert.throws(() => unseal(original.envelope, {...original.key, key: randomBytes(32).toString('base64')}));
  assert.throws(() => unseal(original.envelope, {...original.key, id: randomBytes(16).toString('hex')}));
});

test('strict wire schema rejects keys, plaintext, bad base64, oversized and unknown fields', () => {
  const value = JSON.parse(seal(Buffer.from('test')).envelope);
  for (const invalid of [{...value, key: 'forbidden'}, {...value, plaintext: 'forbidden'},
    {...value, nonce: 'a'}, {...value, tag: '!!!!'}, {...value, version: 2},
    {...value, ciphertext: Buffer.alloc(MAX_PLAINTEXT + 1).toString('base64')}, null, []]) {
    assert.throws(() => validateEnvelope(invalid));
  }
});

test('fresh CLI processes keep key private, preserve binary input, refuse overwrite and unsafe key files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ephem-client-'));
  const run = (...args) => spawnSync(process.execPath, ['zero/client.mjs', ...args], {encoding: 'utf8', timeout: 6000});
  try {
    const input = join(dir, 'input'); const key = join(dir, 'key'); const envelope = join(dir, 'envelope'); const output = join(dir, 'output');
    const data = randomBytes(8193); writeFileSync(input, data);
    assert.equal(run('seal', '--input', input, '--envelope', envelope, '--key', key).status, 0);
    assert.equal(statSync(key).mode & 0o777, 0o600);
    const opened = run('open', '--envelope', envelope, '--key', key, '--output', output);
    assert.equal(opened.status, 0); assert.deepEqual(readFileSync(output), data);
    assert.equal(run('open', '--envelope', envelope, '--key', key, '--output', output).status, 1);
    assert.deepEqual(readFileSync(output), data);
    chmodSync(key, 0o644);
    const forbidden = join(dir, 'forbidden');
    assert.equal(run('open', '--envelope', envelope, '--key', key, '--output', forbidden).status, 1);
    assert.equal(existsSync(forbidden), false);
    const linked = join(dir, 'linked'); symlinkSync(key, linked);
    assert.equal(run('open', '--envelope', envelope, '--key', linked, '--output', forbidden).status, 1);
    chmodSync(key, 0o600);
    const changed = JSON.parse(readFileSync(envelope)); changed.tag = randomBytes(16).toString('base64');
    const tampered = join(dir, 'tampered'); writeFileSync(tampered, JSON.stringify(changed));
    assert.equal(run('open', '--envelope', tampered, '--key', key, '--output', forbidden).status, 1);
    assert.equal(existsSync(forbidden), false);
    assert.equal(opened.stdout.includes(data.toString('base64')), false);
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('CLI rejects oversized files and unsupported inputs without waiting for a FIFO writer', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ephem-client-input-'));
  const run = input => spawnSync(process.execPath, ['zero/client.mjs', 'seal', '--input', input,
    '--envelope', join(dir, 'envelope'), '--key', join(dir, 'key')], {encoding: 'utf8', timeout: 2000});
  try {
    const input = join(dir, 'oversized'); writeFileSync(input, Buffer.alloc(MAX_PLAINTEXT + 1));
    const fifo = join(dir, 'fifo');
    assert.equal(spawnSync('mkfifo', [fifo], {timeout: 2000}).status, 0);
    for (const source of [input, fifo, dir]) {
      const result = run(source);
      assert.equal(result.error, undefined);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, 'ephem-zero: operation rejected\n');
      assert.equal(existsSync(join(dir, 'key')), false);
      assert.equal(existsSync(join(dir, 'envelope')), false);
    }
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('CLI detects a real input file growing between its size check and read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ephem-client-race-'));
  try {
    const input = join(dir, 'input'); const preload = join(dir, 'grow.mjs');
    // Deterministic race scheduling around the actual CLI filesystem call; no
    // production helper or policy bypass is exported for the test.
    writeFileSync(preload, `
      import fs from 'node:fs';
      import {syncBuiltinESMExports} from 'node:module';
      const input = process.env.EPHEM_TEST_INPUT;
      const inode = fs.statSync(input, {bigint: true}).ino;
      const original = fs.fstatSync;
      let changed = false;
      fs.fstatSync = (...args) => {
        const result = original(...args);
        if (!changed && BigInt(result.ino) === inode) {
          changed = true;
          fs.appendFileSync(input, Buffer.alloc(Number(process.env.EPHEM_TEST_GROWTH), 65));
        }
        return result;
      };
      syncBuiltinESMExports();
    `);
    for (const growth of [7, MAX_PLAINTEXT + 1]) {
      writeFileSync(input, 'initial');
      const key = join(dir, `key-${growth}`); const envelope = join(dir, `envelope-${growth}`);
      const result = spawnSync(process.execPath, ['--import', preload, 'zero/client.mjs', 'seal',
        '--input', input, '--envelope', envelope, '--key', key], {encoding: 'utf8', timeout: 2000,
        env: {...process.env, EPHEM_TEST_INPUT: input, EPHEM_TEST_GROWTH: String(growth)}});
      assert.equal(result.error, undefined);
      assert.equal(statSync(input).size, 'initial'.length + growth);
      assert.equal(result.status, 1);
      assert.equal(result.stderr, 'ephem-zero: operation rejected\n');
      assert.equal(existsSync(key), false); assert.equal(existsSync(envelope), false);
    }
  } finally { rmSync(dir, {recursive: true, force: true}); }
});
