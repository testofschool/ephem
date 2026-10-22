// Public wire format. There is deliberately no key field or server decryption API.
export const MAX_PLAINTEXT = 512 * 1024;
const FIELDS = ['version', 'suite', 'id', 'nonce', 'ciphertext', 'tag'];

export function canonicalBase64(value, length, maximum = length) {
  if (typeof value !== 'string' || value.length % 4 !== 0
      || value.length > Math.ceil(maximum / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('invalid base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || bytes.length < length || bytes.length > maximum) {
    throw new Error('invalid byte length');
  }
  return bytes;
}

export function validateEnvelope(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== FIELDS.length
      || Object.keys(value).some(key => !FIELDS.includes(key))
      || value.version !== 1 || value.suite !== 'AES-256-GCM'
      || typeof value.id !== 'string' || !/^[0-9a-f]{32}$/.test(value.id)) {
    throw new Error('invalid sealed envelope');
  }
  canonicalBase64(value.nonce, 12);
  canonicalBase64(value.tag, 16);
  canonicalBase64(value.ciphertext, 0, MAX_PLAINTEXT);
  return Buffer.from(JSON.stringify(Object.fromEntries(FIELDS.map(key => [key, value[key]]))));
}

export function associatedData(id) {
  if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) throw new Error('invalid envelope id');
  return Buffer.from(`EPHEM-SEALED-V1:${id}`, 'ascii');
}
