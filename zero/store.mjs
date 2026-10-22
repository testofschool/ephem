import { randomBytes } from 'node:crypto';

export const MAX_TTL_MS = 60_000;
export const MAX_ENVELOPE_BYTES = 1024 * 1024;
export const MAX_TOTAL_BYTES = 8 * 1024 * 1024;

export class StoreError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function boundedInteger(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`invalid ${name}`);
  }
  return value;
}

/** RAM only, bounded, at-most-once ciphertext ownership. No plaintext or keys. */
export class CiphertextStore {
  #entries = new Map();
  #bytes = 0;
  #closed = false;
  #timer;
  #now;

  constructor({ ttlMs = 30_000, maxSlots = 16, maxEnvelopeBytes = MAX_ENVELOPE_BYTES,
    maxTotalBytes = MAX_TOTAL_BYTES, now = () => performance.now(), sweepMs = 250 } = {}) {
    this.ttlMs = boundedInteger(ttlMs, 1, MAX_TTL_MS, 'ttl');
    this.maxSlots = boundedInteger(maxSlots, 1, 1024, 'slots');
    this.maxEnvelopeBytes = boundedInteger(maxEnvelopeBytes, 1, MAX_ENVELOPE_BYTES, 'envelope cap');
    this.maxTotalBytes = boundedInteger(maxTotalBytes, 1, MAX_TOTAL_BYTES, 'aggregate cap');
    boundedInteger(sweepMs, 1, MAX_TTL_MS, 'sweep interval');
    if (typeof now !== 'function') throw new TypeError('invalid clock');
    this.#now = now;
    this.#timer = setInterval(() => this.sweep(), sweepMs);
    this.#timer.unref();
  }

  put(ciphertext) {
    if (this.#closed) throw new StoreError('closed');
    this.sweep();
    if (!Buffer.isBuffer(ciphertext) || ciphertext.length === 0 ||
      ciphertext.length > this.maxEnvelopeBytes) throw new StoreError('size');
    if (this.#entries.size >= this.maxSlots ||
      this.#bytes + ciphertext.length > this.maxTotalBytes) throw new StoreError('full');
    let token;
    do { token = randomBytes(32).toString('hex'); } while (this.#entries.has(token));
    // Own the copy; a caller cannot mutate retained ciphertext after validation.
    const bytes = Buffer.from(ciphertext);
    this.#entries.set(token, { bytes, expiresAt: this.#now() + this.ttlMs });
    this.#bytes += bytes.length;
    return { token, expiresInMs: this.ttlMs };
  }

  take(token) {
    if (this.#closed) return undefined;
    this.sweep();
    const entry = this.#entries.get(token);
    if (!entry) return undefined;
    // Claim synchronously before any network write or await. The recipient owns
    // this buffer and must overwrite it after writing (including failed writes).
    this.#entries.delete(token);
    this.#bytes -= entry.bytes.length;
    return entry.bytes;
  }

  sweep() {
    const now = this.#now();
    for (const [token, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#drop(token, entry);
    }
  }

  #drop(token, entry) {
    entry.bytes.fill(0);
    this.#bytes -= entry.bytes.length;
    this.#entries.delete(token);
  }

  stats() {
    this.sweep();
    return { objects: this.#entries.size, bytes: this.#bytes };
  }

  /** Test audit only: copies, never exposed through the HTTP service. */
  snapshotCiphertexts() {
    this.sweep();
    return [...this.#entries.values()].map(({ bytes }) => Buffer.from(bytes));
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    clearInterval(this.#timer);
    for (const [token, entry] of this.#entries) this.#drop(token, entry);
  }
}
