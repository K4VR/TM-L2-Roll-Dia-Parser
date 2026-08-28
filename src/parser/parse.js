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

const MSG_ROLL_PARAMETERS = 11;
const MAX_REASONABLE_MSG_LEN = 4096;
const FIXED_FRAME_SKIP = 54; // Ethernet 14 + IPv4 20 + TCP 20 (no options)

function looksLikeMsg11(bytes, offset) {
  if (offset + 8 > bytes.length) return false;
  const msg = readWord(bytes, offset);
  const length = readWord(bytes, offset + 2);
  if (msg !== MSG_ROLL_PARAMETERS) return false;
  if (length < 8 || length > MAX_REASONABLE_MSG_LEN) return false;
  return bytes.length - offset >= 8;
}

/**
 * Find Ethernet / IPv4 / TCP payload start.
 * Standard headers with no VLAN or TCP options are 54 bytes.
 */
export function tcpPayloadOffset(bytes) {
  if (bytes.length < 54) return null;
  if (bytes[12] === undefined || bytes[13] === undefined) return null;

  let i = 14;
  let etherType = (bytes[12] << 8) | bytes[13];
  if (etherType === 0x8100) {
    if (bytes.length < 18) return null;
    etherType = (bytes[16] << 8) | bytes[17];
    i = 18;
  }
  if (etherType !== 0x0800) return null;

  const version = bytes[i] >> 4;
  const ihl = (bytes[i] & 0x0f) * 4;
  if (version !== 4 || ihl < 20) return null;
  if (bytes[i + 9] !== 6) return null;

  const tcpStart = i + ihl;
  if (tcpStart + 20 > bytes.length) return null;
  const tcpLen = ((bytes[tcpStart + 12] >> 4) & 0x0f) * 4;
  if (tcpLen < 20) return null;
  const payload = tcpStart + tcpLen;
  if (payload > bytes.length) return null;
  return payload;
}

/**
 * Skip link/transport framing so a full Wireshark frame paste works.
 * Prefers a parsed Ethernet+IPv4+TCP payload, then a 54-byte prefix
 * when Msg 11 starts there, and leaves payload-only pastes unchanged.
 */
export function findPayloadStart(bytes) {
  const tcpStart = tcpPayloadOffset(bytes);
  if (tcpStart != null && looksLikeMsg11(bytes, tcpStart)) return tcpStart;
  if (looksLikeMsg11(bytes, 0)) return 0;
  if (looksLikeMsg11(bytes, FIXED_FRAME_SKIP)) return FIXED_FRAME_SKIP;
  return 0;
}

/**
 * Decode a Msg 11 roll-parameter payload.
 * Throws if the dump cannot cover the 8-byte header.
 */
export function parseRollMessage(hex) {
  const capture = hexToBytes(hex);
  const skippedBytes = findPayloadStart(capture);
  const bytes = capture.slice(skippedBytes);

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
    skippedBytes,
    captureBytes: capture.length,
  };
}

export function formatParseSummary(parsed) {
  const parts = [];
  if (parsed.skippedBytes) {
    parts.push(`Skipped ${parsed.skippedBytes} framing bytes`);
  }
  parts.push(`Parsed ${parsed.totalBytes} bytes — expected ${parsed.expectedBytes} bytes`);
  if (parsed.totalBytes !== parsed.expectedBytes) {
    parts.push('(length mismatch — extra or missing payload bytes)');
  }
  return parts.join(' · ');
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
