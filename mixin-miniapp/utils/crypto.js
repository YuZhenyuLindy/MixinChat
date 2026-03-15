/**
 * Pure JS AES-256-CBC + HMAC-SHA256 encryption for WeChat Mini Program
 * Compatible with the HTML version's output format when using the same key
 *
 * Format: salt(16) + iv(16) + hmac(32) + ciphertext
 * Key derivation: PBKDF2-SHA256, 100000 iterations
 */

// ============ SHA-256 ============
function sha256(message) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rr(v, n) { return (v >>> n) | (v << (32 - n)); }

  let bytes;
  if (message instanceof Uint8Array) {
    bytes = message;
  } else {
    bytes = new Uint8Array(encodeUTF8(message));
  }

  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = ((len + 8) >> 6 << 6) + 64;
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 4, bitLen, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  for (let off = 0; off < padLen; off += 64) {
    const w = new Int32Array(64);
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i-15], 7) ^ rr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rr(w[i-2], 17) ^ rr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  const result = new Uint8Array(32);
  const rdv = new DataView(result.buffer);
  rdv.setUint32(0, h0); rdv.setUint32(4, h1); rdv.setUint32(8, h2); rdv.setUint32(12, h3);
  rdv.setUint32(16, h4); rdv.setUint32(20, h5); rdv.setUint32(24, h6); rdv.setUint32(28, h7);
  return result;
}

// ============ HMAC-SHA256 ============
function hmacSha256(key, message) {
  const blockSize = 64;
  let keyBytes = key instanceof Uint8Array ? key : new Uint8Array(encodeUTF8(key));
  if (keyBytes.length > blockSize) keyBytes = sha256(keyBytes);
  const padded = new Uint8Array(blockSize);
  padded.set(keyBytes);

  const ipad = new Uint8Array(blockSize + message.length);
  const opad = new Uint8Array(blockSize + 32);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = padded[i] ^ 0x36;
    opad[i] = padded[i] ^ 0x5c;
  }
  ipad.set(message, blockSize);
  const inner = sha256(ipad);
  opad.set(inner, blockSize);
  return sha256(opad);
}

// ============ PBKDF2-SHA256 ============
function pbkdf2(password, salt, iterations, keyLen) {
  const pwBytes = typeof password === 'string' ? new Uint8Array(encodeUTF8(password)) : password;
  const numBlocks = Math.ceil(keyLen / 32);
  const dk = new Uint8Array(numBlocks * 32);

  for (let block = 1; block <= numBlocks; block++) {
    const blockBuf = new Uint8Array(salt.length + 4);
    blockBuf.set(salt);
    blockBuf[salt.length] = (block >> 24) & 0xff;
    blockBuf[salt.length + 1] = (block >> 16) & 0xff;
    blockBuf[salt.length + 2] = (block >> 8) & 0xff;
    blockBuf[salt.length + 3] = block & 0xff;

    let u = hmacSha256(pwBytes, blockBuf);
    let result = new Uint8Array(u);

    for (let i = 1; i < iterations; i++) {
      u = hmacSha256(pwBytes, u);
      for (let j = 0; j < 32; j++) result[j] ^= u[j];
    }
    dk.set(result, (block - 1) * 32);
  }
  return dk.slice(0, keyLen);
}

// ============ AES-256 Core ============
const SBOX = new Uint8Array(256);
const RSBOX = new Uint8Array(256);
const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

(function initAES() {
  let p = 1, q = 1;
  do {
    p = p ^ (p << 1) ^ (p & 128 ? 0x11b : 0);
    p &= 0xff;
    q ^= q << 1; q ^= q << 2; q ^= q << 4;
    q ^= q & 128 ? 0x09 : 0; q &= 0xff;
    const xf = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4);
    SBOX[p] = (xf ^ 0x63) & 0xff;
    RSBOX[SBOX[p]] = p;
  } while (p !== 1);
  SBOX[0] = 0x63;
  RSBOX[0x63] = 0;
})();

function expandKey256(key) {
  const w = new Uint32Array(60);
  for (let i = 0; i < 8; i++) {
    w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
  }
  for (let i = 8; i < 60; i++) {
    let t = w[i - 1];
    if (i % 8 === 0) {
      t = ((SBOX[(t >> 16) & 0xff] << 24) | (SBOX[(t >> 8) & 0xff] << 16) |
           (SBOX[t & 0xff] << 8) | SBOX[(t >> 24) & 0xff]) ^ (RCON[i/8 - 1] << 24);
    } else if (i % 8 === 4) {
      t = (SBOX[(t >> 24)] << 24) | (SBOX[(t >> 16) & 0xff] << 16) |
          (SBOX[(t >> 8) & 0xff] << 8) | SBOX[t & 0xff];
    }
    w[i] = w[i - 8] ^ t;
  }
  return w;
}

function aesEncryptBlock(block, rk) {
  let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ rk[0];
  let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ rk[1];
  let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ rk[2];
  let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ rk[3];

  const T0 = new Int32Array(256), T1 = new Int32Array(256);
  const T2 = new Int32Array(256), T3 = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    const s = SBOX[i];
    const x2 = ((s << 1) ^ (s & 0x80 ? 0x1b : 0)) & 0xff;
    const x3 = x2 ^ s;
    T0[i] = (x2 << 24) | (s << 16) | (s << 8) | x3;
    T1[i] = (x3 << 24) | (x2 << 16) | (s << 8) | s;
    T2[i] = (s << 24) | (x3 << 16) | (x2 << 8) | s;
    T3[i] = (s << 24) | (s << 16) | (x3 << 8) | x2;
  }

  for (let r = 1; r < 14; r++) {
    const ri = r * 4;
    const t0 = T0[(s0>>24)&0xff] ^ T1[(s1>>16)&0xff] ^ T2[(s2>>8)&0xff] ^ T3[s3&0xff] ^ rk[ri];
    const t1 = T0[(s1>>24)&0xff] ^ T1[(s2>>16)&0xff] ^ T2[(s3>>8)&0xff] ^ T3[s0&0xff] ^ rk[ri+1];
    const t2 = T0[(s2>>24)&0xff] ^ T1[(s3>>16)&0xff] ^ T2[(s0>>8)&0xff] ^ T3[s1&0xff] ^ rk[ri+2];
    const t3 = T0[(s3>>24)&0xff] ^ T1[(s0>>16)&0xff] ^ T2[(s1>>8)&0xff] ^ T3[s2&0xff] ^ rk[ri+3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  const out = new Uint8Array(16);
  out[0] = SBOX[(s0>>24)&0xff]^(rk[56]>>24); out[1] = SBOX[(s1>>16)&0xff]^((rk[56]>>16)&0xff);
  out[2] = SBOX[(s2>>8)&0xff]^((rk[56]>>8)&0xff); out[3] = SBOX[s3&0xff]^(rk[56]&0xff);
  out[4] = SBOX[(s1>>24)&0xff]^(rk[57]>>24); out[5] = SBOX[(s2>>16)&0xff]^((rk[57]>>16)&0xff);
  out[6] = SBOX[(s3>>8)&0xff]^((rk[57]>>8)&0xff); out[7] = SBOX[s0&0xff]^(rk[57]&0xff);
  out[8] = SBOX[(s2>>24)&0xff]^(rk[58]>>24); out[9] = SBOX[(s3>>16)&0xff]^((rk[58]>>16)&0xff);
  out[10] = SBOX[(s0>>8)&0xff]^((rk[58]>>8)&0xff); out[11] = SBOX[s1&0xff]^(rk[58]&0xff);
  out[12] = SBOX[(s3>>24)&0xff]^(rk[59]>>24); out[13] = SBOX[(s0>>16)&0xff]^((rk[59]>>16)&0xff);
  out[14] = SBOX[(s1>>8)&0xff]^((rk[59]>>8)&0xff); out[15] = SBOX[s2&0xff]^(rk[59]&0xff);
  return out;
}

function aesDecryptBlock(block, rk) {
  // Build inverse T-tables
  const T0i = new Int32Array(256), T1i = new Int32Array(256);
  const T2i = new Int32Array(256), T3i = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    const s = RSBOX[i];
    const x2 = ((s << 1) ^ (s & 0x80 ? 0x1b : 0)) & 0xff;
    const x4 = ((x2 << 1) ^ (x2 & 0x80 ? 0x1b : 0)) & 0xff;
    const x8 = ((x4 << 1) ^ (x4 & 0x80 ? 0x1b : 0)) & 0xff;
    const xe = x8 ^ x4 ^ x2, xb = x8 ^ x2 ^ s, xd = x8 ^ x4 ^ s, x9 = x8 ^ s;
    T0i[i] = (xe << 24) | (x9 << 16) | (xd << 8) | xb;
    T1i[i] = (xb << 24) | (xe << 16) | (x9 << 8) | xd;
    T2i[i] = (xd << 24) | (xb << 16) | (xe << 8) | x9;
    T3i[i] = (x9 << 24) | (xd << 16) | (xb << 8) | xe;
  }

  // Build decryption round keys
  const dk = new Uint32Array(60);
  for (let i = 0; i < 60; i++) dk[i] = rk[i];
  for (let r = 1; r < 14; r++) {
    for (let c = 0; c < 4; c++) {
      const w = dk[r*4+c];
      const b0 = (w >> 24) & 0xff, b1 = (w >> 16) & 0xff, b2 = (w >> 8) & 0xff, b3 = w & 0xff;
      const s0 = SBOX[b0], s1 = SBOX[b1], s2 = SBOX[b2], s3 = SBOX[b3];
      dk[r*4+c] = T0i[s0] ^ T1i[s1] ^ T2i[s2] ^ T3i[s3];
    }
  }

  let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ dk[56];
  let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ dk[57];
  let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ dk[58];
  let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ dk[59];

  for (let r = 13; r >= 1; r--) {
    const ri = r * 4;
    const t0 = T0i[(s0>>24)&0xff] ^ T1i[(s3>>16)&0xff] ^ T2i[(s2>>8)&0xff] ^ T3i[s1&0xff] ^ dk[ri];
    const t1 = T0i[(s1>>24)&0xff] ^ T1i[(s0>>16)&0xff] ^ T2i[(s3>>8)&0xff] ^ T3i[s2&0xff] ^ dk[ri+1];
    const t2 = T0i[(s2>>24)&0xff] ^ T1i[(s1>>16)&0xff] ^ T2i[(s0>>8)&0xff] ^ T3i[s3&0xff] ^ dk[ri+2];
    const t3 = T0i[(s3>>24)&0xff] ^ T1i[(s2>>16)&0xff] ^ T2i[(s1>>8)&0xff] ^ T3i[s0&0xff] ^ dk[ri+3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  const out = new Uint8Array(16);
  out[0] = RSBOX[(s0>>24)&0xff]^(dk[0]>>24); out[1] = RSBOX[(s3>>16)&0xff]^((dk[0]>>16)&0xff);
  out[2] = RSBOX[(s2>>8)&0xff]^((dk[0]>>8)&0xff); out[3] = RSBOX[s1&0xff]^(dk[0]&0xff);
  out[4] = RSBOX[(s1>>24)&0xff]^(dk[1]>>24); out[5] = RSBOX[(s0>>16)&0xff]^((dk[1]>>16)&0xff);
  out[6] = RSBOX[(s3>>8)&0xff]^((dk[1]>>8)&0xff); out[7] = RSBOX[s2&0xff]^(dk[1]&0xff);
  out[8] = RSBOX[(s2>>24)&0xff]^(dk[2]>>24); out[9] = RSBOX[(s1>>16)&0xff]^((dk[2]>>16)&0xff);
  out[10] = RSBOX[(s0>>8)&0xff]^((dk[2]>>8)&0xff); out[11] = RSBOX[s3&0xff]^(dk[2]&0xff);
  out[12] = RSBOX[(s3>>24)&0xff]^(dk[3]>>24); out[13] = RSBOX[(s2>>16)&0xff]^((dk[3]>>16)&0xff);
  out[14] = RSBOX[(s1>>8)&0xff]^((dk[3]>>8)&0xff); out[15] = RSBOX[s0&0xff]^(dk[3]&0xff);
  return out;
}

// ============ AES-CBC ============
function aesCbcEncrypt(data, key, iv) {
  const rk = expandKey256(key);
  // PKCS7 padding
  const padLen = 16 - (data.length % 16);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) padded[i] = padLen;

  const out = new Uint8Array(padded.length);
  let prev = new Uint8Array(iv);

  for (let i = 0; i < padded.length; i += 16) {
    const block = new Uint8Array(16);
    for (let j = 0; j < 16; j++) block[j] = padded[i + j] ^ prev[j];
    const encrypted = aesEncryptBlock(block, rk);
    out.set(encrypted, i);
    prev = encrypted;
  }
  return out;
}

function aesCbcDecrypt(data, key, iv) {
  const rk = expandKey256(key);
  const out = new Uint8Array(data.length);
  let prev = new Uint8Array(iv);

  for (let i = 0; i < data.length; i += 16) {
    const block = data.slice(i, i + 16);
    const decrypted = aesDecryptBlock(block, rk);
    for (let j = 0; j < 16; j++) out[i + j] = decrypted[j] ^ prev[j];
    prev = block;
  }

  // Remove PKCS7 padding
  const padLen = out[out.length - 1];
  if (padLen < 1 || padLen > 16) throw new Error('Invalid padding');
  for (let i = out.length - padLen; i < out.length; i++) {
    if (out[i] !== padLen) throw new Error('Invalid padding');
  }
  return out.slice(0, out.length - padLen);
}

// ============ Utility ============
function encodeUTF8(str) {
  const arr = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
      const c2 = str.charCodeAt(i + 1);
      if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
        c = ((c - 0xD800) << 10) + (c2 - 0xDC00) + 0x100000;
        i++;
      }
    }
    if (c < 0x80) arr.push(c);
    else if (c < 0x800) { arr.push(0xC0 | (c >> 6)); arr.push(0x80 | (c & 0x3F)); }
    else if (c < 0x100000) { arr.push(0xE0 | (c >> 12)); arr.push(0x80 | ((c >> 6) & 0x3F)); arr.push(0x80 | (c & 0x3F)); }
    else { arr.push(0xF0 | (c >> 18)); arr.push(0x80 | ((c >> 12) & 0x3F)); arr.push(0x80 | ((c >> 6) & 0x3F)); arr.push(0x80 | (c & 0x3F)); }
  }
  return arr;
}

function decodeUTF8(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length;) {
    const b = bytes[i];
    let c;
    if (b < 0x80) { c = b; i++; }
    else if (b < 0xE0) { c = ((b & 0x1F) << 6) | (bytes[i+1] & 0x3F); i += 2; }
    else if (b < 0xF0) { c = ((b & 0x0F) << 12) | ((bytes[i+1] & 0x3F) << 6) | (bytes[i+2] & 0x3F); i += 3; }
    else { c = ((b & 0x07) << 18) | ((bytes[i+1] & 0x3F) << 12) | ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F); i += 4; }
    if (c > 0xFFFF) {
      c -= 0x100000;
      str += String.fromCharCode(0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF));
    } else {
      str += String.fromCharCode(c);
    }
  }
  return str;
}

function randomBytes(n) {
  const arr = new Uint8Array(n);
  for (let i = 0; i < n; i++) arr[i] = Math.floor(Math.random() * 256);
  return arr;
}

function toBase64(bytes) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b1 = bytes[i], b2 = i + 1 < bytes.length ? bytes[i+1] : 0, b3 = i + 2 < bytes.length ? bytes[i+2] : 0;
    result += chars[b1 >> 2] + chars[((b1 & 3) << 4) | (b2 >> 4)];
    result += i + 1 < bytes.length ? chars[((b2 & 0xf) << 2) | (b3 >> 6)] : '=';
    result += i + 2 < bytes.length ? chars[b3 & 0x3f] : '=';
  }
  return result;
}

function fromBase64(str) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = {};
  for (let i = 0; i < chars.length; i++) lookup[chars[i]] = i;
  str = str.replace(/[^A-Za-z0-9+/]/g, '');
  const len = str.length;
  const bytes = new Uint8Array(Math.floor(len * 3 / 4));
  let p = 0;
  for (let i = 0; i < len; i += 4) {
    const a = lookup[str[i]] || 0, b = lookup[str[i+1]] || 0;
    const c = lookup[str[i+2]] || 0, d = lookup[str[i+3]] || 0;
    bytes[p++] = (a << 2) | (b >> 4);
    if (i + 2 < len) bytes[p++] = ((b & 0xf) << 4) | (c >> 2);
    if (i + 3 < len) bytes[p++] = ((c & 3) << 6) | d;
  }
  return bytes.slice(0, p);
}

// ============ Public API ============
// Format: salt(16) + iv(16) + hmac(32) + ciphertext
function encrypt(plaintext, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const derived = pbkdf2(password, salt, 100000, 64); // 32 for AES key, 32 for HMAC key
  const aesKey = derived.slice(0, 32);
  const hmacKey = derived.slice(32, 64);
  const textBytes = new Uint8Array(encodeUTF8(plaintext));
  const ciphertext = aesCbcEncrypt(textBytes, aesKey, iv);

  // HMAC over salt + iv + ciphertext
  const toMac = new Uint8Array(salt.length + iv.length + ciphertext.length);
  toMac.set(salt, 0);
  toMac.set(iv, salt.length);
  toMac.set(ciphertext, salt.length + iv.length);
  const mac = hmacSha256(hmacKey, toMac);

  // Combined: salt + iv + hmac + ciphertext
  const combined = new Uint8Array(16 + 16 + 32 + ciphertext.length);
  combined.set(salt, 0);
  combined.set(iv, 16);
  combined.set(mac, 32);
  combined.set(ciphertext, 64);

  return '\u{1F512}' + toBase64(combined);
}

function decrypt(cipherB64, password) {
  if (cipherB64.startsWith('\u{1F512}')) cipherB64 = cipherB64.slice(2);
  cipherB64 = cipherB64.trim();

  const raw = fromBase64(cipherB64);
  if (raw.length < 65) throw new Error('数据格式错误');

  const salt = raw.slice(0, 16);
  const iv = raw.slice(16, 32);
  const mac = raw.slice(32, 64);
  const ciphertext = raw.slice(64);

  const derived = pbkdf2(password, salt, 100000, 64);
  const aesKey = derived.slice(0, 32);
  const hmacKey = derived.slice(32, 64);

  // Verify HMAC
  const toMac = new Uint8Array(16 + 16 + ciphertext.length);
  toMac.set(salt, 0);
  toMac.set(iv, 16);
  toMac.set(ciphertext, 32);
  const expectedMac = hmacSha256(hmacKey, toMac);

  let macOk = true;
  for (let i = 0; i < 32; i++) {
    if (mac[i] !== expectedMac[i]) macOk = false;
  }
  if (!macOk) throw new Error('密钥错误或数据被篡改');

  const plainBytes = aesCbcDecrypt(ciphertext, aesKey, iv);
  return decodeUTF8(plainBytes);
}

function generateRandomKey() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let key = '';
  const arr = randomBytes(16);
  for (let i = 0; i < arr.length; i++) key += chars[arr[i] % chars.length];
  return key;
}

module.exports = { encrypt, decrypt, generateRandomKey };
