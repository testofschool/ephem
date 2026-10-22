#!/usr/bin/env node
// Install this client independently of the relay. It never loads remote code.
import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';
import {constants, openSync, closeSync, fstatSync, readSync, writeFileSync, unlinkSync, lstatSync} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import {pathToFileURL} from 'node:url';
import {MAX_PLAINTEXT, canonicalBase64, validateEnvelope, associatedData} from './envelope.mjs';

const MAX_WIRE = 720 * 1024;

export function seal(plaintext) {
  if (!Buffer.isBuffer(plaintext) || plaintext.length > MAX_PLAINTEXT) throw new Error('input limit');
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const id = randomBytes(16).toString('hex');
  const cipher = createCipheriv('aes-256-gcm', key, nonce, {authTagLength: 16});
  cipher.setAAD(associatedData(id));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = {version: 1, suite: 'AES-256-GCM', id, nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'), tag: cipher.getAuthTag().toString('base64')};
  return {envelope: validateEnvelope(envelope), key: {version: 1, id, key: key.toString('base64')}};
}

export function unseal(envelopeBytes, keyRecord) {
  const envelope = JSON.parse(envelopeBytes);
  validateEnvelope(envelope);
  if (!keyRecord || Object.keys(keyRecord).sort().join(',') !== 'id,key,version'
      || keyRecord.version !== 1 || keyRecord.id !== envelope.id) throw new Error('wrong key record');
  const key = canonicalBase64(keyRecord.key, 32);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, canonicalBase64(envelope.nonce, 12), {authTagLength: 16});
    decipher.setAAD(associatedData(envelope.id));
    decipher.setAuthTag(canonicalBase64(envelope.tag, 16));
    // Nothing is written to the caller until final() authenticates every byte.
    return Buffer.concat([decipher.update(canonicalBase64(envelope.ciphertext, 0, MAX_PLAINTEXT)), decipher.final()]);
  } finally { key.fill(0); }
}

function readRegular(path, limit, privateFile = false) {
  // NONBLOCK makes a substituted FIFO fail inspection rather than hang open().
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let scratch;
  try {
    const stat = fstatSync(fd, {bigint: true});
    if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(limit)
        || (privateFile && ((stat.mode & 0o077n) !== 0n || stat.uid !== BigInt(process.getuid())))) {
      throw new Error('unsafe input file');
    }
    // fstat size is only a snapshot. Never let a growing file make readFileSync
    // allocate beyond the command's declared input cap.
    scratch = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < scratch.length) {
      const count = readSync(fd, scratch, length, scratch.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd, {bigint: true});
    if (length > limit || BigInt(length) !== stat.size || !after.isFile()
        || after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size
        || after.nlink !== stat.nlink || after.mode !== stat.mode || after.uid !== stat.uid
        || after.mtimeNs !== stat.mtimeNs || after.ctimeNs !== stat.ctimeNs) {
      throw new Error('input file changed while reading');
    }
    return Buffer.from(scratch.subarray(0, length));
  } finally { scratch?.fill(0); closeSync(fd); }
}

function createPrivate(path, bytes) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  const identity = fstatSync(fd);
  try { writeFileSync(fd, bytes); }
  catch (error) {
    try {
      const now = lstatSync(path);
      if (now.dev === identity.dev && now.ino === identity.ino) unlinkSync(path);
    } catch {}
    throw error;
  } finally { closeSync(fd); }
}

export async function exchange(base, endpoint, bytes) {
  const url = new URL(base);
  if (url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)
      || !(url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)))) {
    throw new Error('HTTPS or loopback URL required');
  }
  url.pathname = endpoint;
  return await new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, {method: 'POST', headers: {
      'Content-Type': 'application/json', 'Content-Length': bytes.length, 'Connection': 'close',
    }}, response => {
      const chunks = []; let size = 0;
      response.on('data', block => {
        size += block.length;
        if (size > MAX_WIRE) response.destroy(new Error('response limit'));
        else chunks.push(block);
      });
      response.on('error', error => { clearTimeout(timer); reject(error); });
      response.on('end', () => {
        clearTimeout(timer);
        if (![200, 201].includes(response.statusCode)) reject(new Error('relay rejected request'));
        else resolve(Buffer.concat(chunks));
      });
    });
    const timer = setTimeout(() => request.destroy(new Error('request deadline')), 5000);
    request.on('error', error => { clearTimeout(timer); reject(error); });
    request.end(bytes);
  });
}

export async function main(argv) {
  const [command, ...rest] = argv;
  const opts = {};
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index]; const value = rest[index + 1];
    if (!/^--[a-z]+$/.test(name ?? '') || value === undefined || name in opts) throw new Error('bad arguments');
    opts[name] = value;
  }
  const required = {seal: ['--input', '--envelope', '--key'], put: ['--url', '--envelope', '--receipt'],
    take: ['--url', '--receipt', '--envelope'], open: ['--envelope', '--key', '--output']}[command];
  if (!required || required.length !== Object.keys(opts).length || required.some(name => !(name in opts))) {
    throw new Error('usage: seal|put|take|open with required file options');
  }
  if (command === 'seal') {
    const plain = readRegular(opts['--input'], MAX_PLAINTEXT);
    try {
      const sealed = seal(plain);
      // Key stays in this client filesystem; put/take never read this file.
      createPrivate(opts['--key'], Buffer.from(JSON.stringify(sealed.key)));
      createPrivate(opts['--envelope'], sealed.envelope);
    } finally { plain.fill(0); }
  } else if (command === 'open') {
    const plain = unseal(readRegular(opts['--envelope'], MAX_WIRE),
      JSON.parse(readRegular(opts['--key'], 1024, true)));
    try { createPrivate(opts['--output'], plain); } finally { plain.fill(0); }
  } else if (command === 'put') {
    const canonical = validateEnvelope(JSON.parse(readRegular(opts['--envelope'], MAX_WIRE)));
    const receipt = JSON.parse(await exchange(opts['--url'], '/v1/objects', canonical));
    if (!receipt || !/^[0-9a-f]{64}$/.test(receipt.token ?? '')
        || !Number.isSafeInteger(receipt.expiresInMs) || receipt.expiresInMs < 1 || receipt.expiresInMs > 60000) {
      throw new Error('bad receipt');
    }
    createPrivate(opts['--receipt'], Buffer.from(JSON.stringify(receipt)));
  } else {
    const receipt = JSON.parse(readRegular(opts['--receipt'], 1024, true));
    if (!/^[0-9a-f]{64}$/.test(receipt.token ?? '')) throw new Error('bad receipt');
    const response = await exchange(opts['--url'], '/v1/take', Buffer.from(JSON.stringify({token: receipt.token})));
    createPrivate(opts['--envelope'], validateEnvelope(JSON.parse(response)));
  }
  process.stdout.write(JSON.stringify({ok: true, operation: command}) + '\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(() => { process.stderr.write('ephem-zero: operation rejected\n'); process.exitCode = 1; });
}
