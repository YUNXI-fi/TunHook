// 轻量二维码编码器：字节模式、纠错等级 L、版本 1-6。
// 仅用于控制台里展示当前服务地址，超过 134 字节时返回空字符串。
import { tr } from './i18n.js';

const DATA_CODEWORDS = [19, 34, 55, 80, 108, 136];
const ECC_CODEWORDS = [7, 10, 15, 20, 26, 18];
const BLOCKS = [1, 1, 1, 1, 1, 2];
const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34]];

const EXP = new Array(512);
const LOG = new Array(256);
let acc = 1;
for (let i = 0; i < 255; i++) {
  EXP[i] = acc;
  LOG[acc] = i;
  acc <<= 1;
  if (acc & 0x100) acc ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];

function gfMul(a, b) {
  if (!a || !b) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function rsGenerator(n) {
  let poly = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data, gen) {
  const res = new Array(gen.length - 1).fill(0);
  for (let d = 0; d < data.length; d++) {
    const factor = data[d] ^ res[0];
    res.shift();
    res.push(0);
    if (factor) {
      for (let i = 0; i < gen.length - 1; i++) res[i] ^= gfMul(gen[i + 1], factor);
    }
  }
  return res;
}

function chooseVersion(len) {
  for (let v = 1; v <= 6; v++) {
    if (4 + 8 + 8 * len <= DATA_CODEWORDS[v - 1] * 8) return v;
  }
  return 0;
}

function makeCodewords(bytes, version) {
  const capacity = DATA_CODEWORDS[version - 1];
  const bits = [];
  const push = (value, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(4, 4);
  push(bytes.length, 8);
  for (let i = 0; i < bytes.length; i++) push(bytes[i], 8);
  const capBits = capacity * 8;
  for (let i = 0; i < 4 && bits.length < capBits; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    data.push(v);
  }
  const pads = [0xec, 0x11];
  let p = 0;
  while (data.length < capacity) data.push(pads[p++ % 2]);

  const blockCount = BLOCKS[version - 1];
  const perBlock = capacity / blockCount;
  const ecLen = ECC_CODEWORDS[version - 1];
  const dataBlocks = [];
  const ecBlocks = [];
  for (let b = 0; b < blockCount; b++) {
    const block = data.slice(b * perBlock, (b + 1) * perBlock);
    dataBlocks.push(block);
    ecBlocks.push(rsRemainder(block, rsGenerator(ecLen)));
  }
  if (blockCount === 1) return data.concat(ecBlocks[0]);
  const out = [];
  for (let i = 0; i < perBlock; i++) {
    for (let b = 0; b < blockCount; b++) out.push(dataBlocks[b][i]);
  }
  for (let i = 0; i < ecLen; i++) {
    for (let b = 0; b < blockCount; b++) out.push(ecBlocks[b][i]);
  }
  return out;
}

function maskBit(mask, r, c) {
  switch (mask) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
}

function formatBits(mask) {
  const data = (1 << 3) | mask; // 纠错等级 L = 01
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

function buildMatrix(version, codewords, mask) {
  const size = 17 + version * 4;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (r, c, dark) => {
    modules[r][c] = dark;
    reserved[r][c] = true;
  };

  const finders = [[0, 0], [0, size - 7], [size - 7, 0]];
  for (let f = 0; f < finders.length; f++) {
    const br = finders[f][0];
    const bc = finders[f][1];
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = br + dr;
        const c = bc + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const dark =
          (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6)) ||
          (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6)) ||
          (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
        set(r, c, dark);
      }
    }
  }

  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }

  const pos = ALIGN[version - 1];
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      const r = pos[i];
      const c = pos[j];
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
      }
    }
  }

  set(size - 8, 8, true);

  for (let i = 0; i < 9; i++) {
    if (!reserved[8][i]) { reserved[8][i] = true; modules[8][i] = false; }
    if (!reserved[i][8]) { reserved[i][8] = true; modules[i][8] = false; }
  }
  for (let i = 0; i < 8; i++) {
    reserved[8][size - 1 - i] = true;
    modules[8][size - 1 - i] = false;
  }
  for (let i = 0; i < 7; i++) {
    reserved[size - 1 - i][8] = true;
    modules[size - 1 - i][8] = false;
  }

  let bitIndex = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (let k = 0; k < 2; k++) {
        const c = col - k;
        if (reserved[row][c]) continue;
        let bit = false;
        if (bitIndex < codewords.length * 8) {
          bit = ((codewords[bitIndex >> 3] >>> (7 - (bitIndex & 7))) & 1) === 1;
          bitIndex++;
        }
        modules[row][c] = bit !== maskBit(mask, row, c);
      }
    }
    upward = !upward;
  }

  const bits = formatBits(mask);
  const getBit = (v, i) => ((v >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(i, 8, getBit(bits, i));
  set(7, 8, getBit(bits, 6));
  set(8, 8, getBit(bits, 7));
  set(8, 7, getBit(bits, 8));
  for (let i = 9; i <= 14; i++) set(8, 14 - i, getBit(bits, i));
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, getBit(bits, i));
  for (let i = 8; i <= 14; i++) set(size - 15 + i, 8, getBit(bits, i));
  set(size - 8, 8, true);

  return modules;
}

function penalty(m) {
  const n = m.length;
  let p = 0;
  for (let r = 0; r < n; r++) {
    let run = 1;
    for (let c = 1; c < n; c++) {
      if (m[r][c] === m[r][c - 1]) run++;
      else {
        if (run >= 5) p += 3 + (run - 5);
        run = 1;
      }
    }
    if (run >= 5) p += 3 + (run - 5);
  }
  for (let c = 0; c < n; c++) {
    let run = 1;
    for (let r = 1; r < n; r++) {
      if (m[r][c] === m[r - 1][c]) run++;
      else {
        if (run >= 5) p += 3 + (run - 5);
        run = 1;
      }
    }
    if (run >= 5) p += 3 + (run - 5);
  }
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) p += 3;
    }
  }
  for (let r = 0; r < n; r++) {
    let row = '';
    for (let c = 0; c < n; c++) row += m[r][c] ? '1' : '0';
    for (let i = 0; i <= n - 11; i++) {
      const s = row.slice(i, i + 11);
      if (s === '00001011101' || s === '10111010000') p += 40;
    }
  }
  for (let c = 0; c < n; c++) {
    let col = '';
    for (let r = 0; r < n; r++) col += m[r][c] ? '1' : '0';
    for (let i = 0; i <= n - 11; i++) {
      const s = col.slice(i, i + 11);
      if (s === '00001011101' || s === '10111010000') p += 40;
    }
  }
  let dark = 0;
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) if (m[r][c]) dark++;
  }
  p += Math.floor(Math.abs((dark * 100) / (n * n) - 50) / 5) * 10;
  return p;
}

function encodeQr(text) {
  const value = String(text || '').trim();
  if (!value) return null;
  const bytes = new TextEncoder().encode(value);
  const version = chooseVersion(bytes.length);
  if (!version) return null;
  const codewords = makeCodewords(bytes, version);
  let best = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const matrix = buildMatrix(version, codewords, mask);
    const score = penalty(matrix);
    if (score < bestScore) {
      bestScore = score;
      best = matrix;
    }
  }
  return best;
}

/**
 * 生成二维码 SVG 字符串。
 * @param {string} text 要编码的内容
 * @returns {string} 可直接用于 {@html} 的 SVG；内容过长或为空时返回空字符串
 */
export function qrSvg(text) {
  const best = encodeQr(text);
  if (!best) return '';
  const size = best.length;
  const margin = 2;
  const dim = size + margin * 2;
  let edge = '';
  for (let r = 0; r < size; r++) {
    let start = -1;
    for (let c = 0; c <= size; c++) {
      const dark = c < size && best[r][c];
      if (dark && start < 0) start = c;
      if (!dark && start >= 0) {
        edge += 'M' + (start + margin) + ' ' + (r + margin) + 'h' + (c - start) + 'v1h-' + (c - start) + 'z';
        start = -1;
      }
    }
  }
  return (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dim + ' ' + dim +
    '" shape-rendering="crispEdges" role="img" aria-label="' + tr('扫码访问') + '"><path d="' + edge +
    '" fill="#0a1119"/></svg>'
  );
}
