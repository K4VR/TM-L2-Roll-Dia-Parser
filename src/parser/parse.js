import { FIELDS, EXPECTED_BYTES } from './fields.js';

const WIRESHARK_OFFSET =
  /^(?:0x)?[0-9A-Fa-f]{4,8}(?::\s+|\s{2,})[0-9A-Fa-f]{2}/;

/**
 * Convert pasted hex (raw stream or Wireshark-style dump) into a byte array.
 * Dump offsets and ASCII trailers are stripped so they are not decoded as payload.
 */
export function hexToBytes(hex) {
  const text = String(hex ?? '').trim();
  if (!text) return [];

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const dumpLines = lines.filter((line) => looksLikeDumpLine(line));

  if (dumpLines.length > 0 && dumpLines.length >= Math.ceil(lines.length * 0.4)) {
    const bytes = [];
    for (const line of dumpLines) {
      bytes.push(...bytesFromDumpLine(line));
    }
    return bytes;
  }

  const cleaned = text.replace(/0x/gi, '').replace(/[^0-9A-Fa-f]/g, '');
  const bytes = [];
  for (let i = 0; i + 1 < cleaned.length; i += 2) {
    bytes.push(parseInt(cleaned.slice(i, i + 2), 16));
  }
  return bytes;
}

function looksLikeDumpLine(line) {
  if (/offset|ascii|hex dump/i.test(line)) return false;
  return WIRESHARK_OFFSET.test(line);
}

function bytesFromDumpLine(line) {
  const withoutAsciiPipes = line.replace(/\s*\|.*\|?\s*$/, '');
  const rest = withoutAsciiPipes.replace(/^(?:0x)?[0-9A-Fa-f]{4,8}:?\s+/, '');
  const tokens = [];

  for (const part of rest.split(/\s+/)) {
    if (/^[0-9A-Fa-f]{2}$/.test(part)) {
      tokens.push(part);
    } else if (/^[0-9A-Fa-f]{4,}$/.test(part) && part.length % 2 === 0) {
      for (let i = 0; i < part.length; i += 2) tokens.push(part.slice(i, i + 2));
    } else {
      break;
    }
    if (tokens.length >= 16) break;
  }

  return tokens.map((token) => parseInt(token, 16));
}

export function readWord(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

export function readLong(bytes, offset) {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

export function readFloat(bytes, offset) {
  const buffer = new ArrayBuffer(4);
  const view = new DataView(buffer);
  for (let i = 0; i < 4; i++) view.setUint8(i, bytes[offset + i]);
  return view.getFloat32(0, true);
}

export function readString(bytes, offset, length) {
  let str = '';
  for (let i = 0; i < length; i++) {
    const b = bytes[offset + i];
    if (b === 0) break;
    str += String.fromCharCode(b);
  }
  return str;
}

export function getRawHex(bytes, offset, size) {
  return bytes
    .slice(offset, offset + size)
    .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(' ');
}

function decodeField(field, bytes, offset) {
  if (field.type === 'Word') return readWord(bytes, offset).toString();
  if (field.type === 'Long') return readLong(bytes, offset).toString();
  if (field.type === 'REAL') return readFloat(bytes, offset).toFixed(6);
  if (field.type === 'Byte*16') return readString(bytes, offset, field.size);
  return '';
}

/**
 * Decode a Msg 11 roll-parameter payload.
 * Throws if the dump cannot cover the 8-byte header.
 */
export function parseRollMessage(hex) {
  const bytes = hexToBytes(hex);

  if (bytes.length < 8) {
    const error = new Error(
      `Hex dump too short. Got ${bytes.length} bytes, need at least 8 for the header.`,
    );
    error.code = 'TOO_SHORT';
    throw error;
  }

  let offset = 0;
  const results = [];

  for (const field of FIELDS) {
    const hasData = offset + field.size <= bytes.length;
    const rawHex = hasData ? getRawHex(bytes, offset, field.size) : '';
    const value = hasData ? decodeField(field, bytes, offset) : '—';
    results.push({ ...field, offset, value, rawHex, hasData });
    offset += field.size;
  }

  return {
    results,
    totalBytes: bytes.length,
    expectedBytes: EXPECTED_BYTES,
  };
}

export function resultsToCsv(parsedData) {
  const header = 'Field Name,Description,Data Type,Byte Size,Offset,Raw Hex,Value,Unit';
  const rows = parsedData.results.map((r) =>
    [r.name, r.desc, r.type, r.size, r.offset, r.rawHex, r.value, r.unit || '']
      .map((c) => `"${String(c).replace(/"/g, '""')}"`)
      .join(','),
  );
  return `${header}\n${rows.join('\n')}\n`;
}

export function csvFilename(date = new Date()) {
  return `roll_diameter_parsed_${date.toISOString().slice(0, 19).replace(/[:.]/g, '-')}.csv`;
}
