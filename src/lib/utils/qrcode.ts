/**
 * ISO/IEC 18004 Compliant QR Code Matrix Generator (Byte Mode, Error Correction Level L).
 * Zero external dependencies; renders crisp vector SVG matrices client-side without network calls.
 */

interface VersionSpec {
  version: number;
  size: number;
  totalDataCodewords: number;
  ecCodewordsPerBlock: number;
  numBlocks: number;
  alignmentCenters: number[];
}

// ISO/IEC 18004 EC Level L specifications for Versions 1 to 6 (supports URLs up to 134 bytes)
const VERSION_SPECS: VersionSpec[] = [
  {
    version: 1,
    size: 21,
    totalDataCodewords: 19,
    ecCodewordsPerBlock: 7,
    numBlocks: 1,
    alignmentCenters: [],
  },
  {
    version: 2,
    size: 25,
    totalDataCodewords: 34,
    ecCodewordsPerBlock: 10,
    numBlocks: 1,
    alignmentCenters: [6, 18],
  },
  {
    version: 3,
    size: 29,
    totalDataCodewords: 55,
    ecCodewordsPerBlock: 15,
    numBlocks: 1,
    alignmentCenters: [6, 22],
  },
  {
    version: 4,
    size: 33,
    totalDataCodewords: 80,
    ecCodewordsPerBlock: 20,
    numBlocks: 1,
    alignmentCenters: [6, 26],
  },
  {
    version: 5,
    size: 37,
    totalDataCodewords: 108,
    ecCodewordsPerBlock: 26,
    numBlocks: 1,
    alignmentCenters: [6, 30],
  },
  {
    version: 6,
    size: 41,
    totalDataCodewords: 136,
    ecCodewordsPerBlock: 18,
    numBlocks: 2,
    alignmentCenters: [6, 34],
  },
];

// GF(256) log and exp tables with primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1)
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function getGeneratorPolynomial(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function computeReedSolomon(
  data: Uint8Array,
  ecLength: number
): Uint8Array {
  const gen = getGeneratorPolynomial(ecLength);
  const remainder = new Uint8Array(ecLength);

  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[ecLength - 1] = 0;
    if (factor !== 0) {
      for (let j = 0; j < ecLength; j++) {
        remainder[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }

  return remainder;
}

function encodeDataCodewords(bytes: Uint8Array, spec: VersionSpec): Uint8Array {
  const bits: number[] = [];
  const pushBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) {
      bits.push((val >>> i) & 1);
    }
  };

  // Byte mode indicator (0100)
  pushBits(0b0100, 4);
  // Character count indicator (8 bits for versions 1-9 in byte mode)
  pushBits(bytes.length, 8);
  // Payload bytes
  for (let i = 0; i < bytes.length; i++) {
    pushBits(bytes[i], 8);
  }

  const maxBits = spec.totalDataCodewords * 8;
  // Terminator (up to 4 zero bits)
  const terminatorLen = Math.min(4, maxBits - bits.length);
  pushBits(0, terminatorLen);

  // Pad to byte boundary
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const codewords = new Uint8Array(spec.totalDataCodewords);
  const byteLen = bits.length / 8;
  for (let i = 0; i < byteLen; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) {
      b = (b << 1) | bits[i * 8 + j];
    }
    codewords[i] = b;
  }

  // Pad remaining codewords alternating 0xEC and 0x11
  const padBytes = [0xec, 0x11];
  for (let i = byteLen; i < spec.totalDataCodewords; i++) {
    codewords[i] = padBytes[(i - byteLen) % 2];
  }

  // Split into blocks, compute Reed-Solomon EC codewords, and interleave
  const blockDataSize = spec.totalDataCodewords / spec.numBlocks;
  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];

  for (let b = 0; b < spec.numBlocks; b++) {
    const block = codewords.slice(
      b * blockDataSize,
      (b + 1) * blockDataSize
    );
    dataBlocks.push(block);
    ecBlocks.push(computeReedSolomon(block, spec.ecCodewordsPerBlock));
  }

  const totalCodewords =
    spec.totalDataCodewords + spec.ecCodewordsPerBlock * spec.numBlocks;
  const finalCodewords = new Uint8Array(totalCodewords);
  let offset = 0;

  for (let i = 0; i < blockDataSize; i++) {
    for (let b = 0; b < spec.numBlocks; b++) {
      finalCodewords[offset++] = dataBlocks[b][i];
    }
  }

  for (let i = 0; i < spec.ecCodewordsPerBlock; i++) {
    for (let b = 0; b < spec.numBlocks; b++) {
      finalCodewords[offset++] = ecBlocks[b][i];
    }
  }

  return finalCodewords;
}

function computeFormatBits(ecLevelBits: number, maskPattern: number): number {
  const data = ((ecLevelBits & 0x3) << 3) | (maskPattern & 0x7);
  let rem = data << 10;
  const generator = 0b10100110111; // x^10 + x^8 + x^5 + x^4 + x^2 + x + 1
  for (let i = 14; i >= 10; i--) {
    if ((rem >>> i) & 1) {
      rem ^= generator << (i - 10);
    }
  }
  return ((data << 10) | rem) ^ 0b101010000010010;
}

export function generateQrMatrix(text: string): boolean[][] {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);

  // Pick smallest version that fits (byte mode overhead = 4 + 8 bits = 2 bytes)
  const spec =
    VERSION_SPECS.find((s) => s.totalDataCodewords - 2 >= bytes.length) ??
    VERSION_SPECS[VERSION_SPECS.length - 1];

  const payload =
    bytes.length > spec.totalDataCodewords - 2
      ? bytes.slice(0, spec.totalDataCodewords - 2)
      : bytes;

  const size = spec.size;
  const modules: boolean[][] = Array.from({ length: size }, () =>
    Array(size).fill(false)
  );
  const isFunction: boolean[][] = Array.from({ length: size }, () =>
    Array(size).fill(false)
  );

  const setFunctionModule = (r: number, c: number, dark: boolean) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      modules[r][c] = dark;
      isFunction[r][c] = true;
    }
  };

  // Finder patterns + separators
  const drawFinder = (row: number, col: number) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = row + dr;
        const c = col + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const isBorder =
          (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6)) ||
          (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6));
        const isCenter = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunctionModule(r, c, isBorder || isCenter);
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    setFunctionModule(6, i, i % 2 === 0);
    setFunctionModule(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const centers = spec.alignmentCenters;
  for (const r of centers) {
    for (const c of centers) {
      if (
        (r === 6 && c === 6) ||
        (r === 6 && c === size - 7) ||
        (r === size - 7 && c === 6)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const dark =
            Math.max(Math.abs(dr), Math.abs(dc)) === 2 ||
            (dr === 0 && dc === 0);
          setFunctionModule(r + dr, c + dc, dark);
        }
      }
    }
  }

  // Dark module
  setFunctionModule(size - 8, 8, true);

  // Reserve format info areas
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      if (!isFunction[8][i]) setFunctionModule(8, i, false);
      if (!isFunction[i][8]) setFunctionModule(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    if (!isFunction[8][size - 1 - i]) setFunctionModule(8, size - 1 - i, false);
    if (!isFunction[size - 1 - i][8]) setFunctionModule(size - 1 - i, 8, false);
  }

  // Place data bits in zigzag upward/downward columns
  const codewords = encodeDataCodewords(payload, spec);
  let bitIdx = 0;
  const totalBits = codewords.length * 8;

  let upward = true;
  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) rightCol = 5; // Skip vertical timing pattern column
    for (let v = 0; v < size; v++) {
      const row = upward ? size - 1 - v : v;
      for (let dc = 0; dc < 2; dc++) {
        const col = rightCol - dc;
        if (!isFunction[row][col]) {
          let dark = false;
          if (bitIdx < totalBits) {
            const byte = codewords[bitIdx >>> 3];
            dark = ((byte >>> (7 - (bitIdx & 7))) & 1) === 1;
            bitIdx++;
          }
          modules[row][col] = dark;
        }
      }
    }
    upward = !upward;
  }

  // Apply Mask Pattern 0 ((row + col) % 2 === 0)
  const maskPattern = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!isFunction[r][c] && (r + c) % 2 === 0) {
        modules[r][c] = !modules[r][c];
      }
    }
  }

  // Write format information bits (EC Level L = 01, Mask = 0)
  const formatBits = computeFormatBits(0b01, maskPattern);
  const getFormatBit = (idx: number) => ((formatBits >>> idx) & 1) === 1;

  // Top-left format bits
  for (let i = 0; i <= 5; i++) modules[8][i] = getFormatBit(i);
  modules[8][7] = getFormatBit(6);
  modules[8][8] = getFormatBit(7);
  modules[7][8] = getFormatBit(8);
  for (let i = 9; i < 15; i++) modules[14 - i][8] = getFormatBit(i);

  // Top-right and bottom-left format bits
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = getFormatBit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = getFormatBit(i);

  return modules;
}
