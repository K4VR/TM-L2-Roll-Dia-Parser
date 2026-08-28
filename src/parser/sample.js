import { FIELDS } from './fields.js';

function padString(value, length) {
  const bytes = Array.from({ length }, () => 0);
  const chars = String(value);
  for (let i = 0; i < Math.min(chars.length, length); i++) {
    bytes[i] = chars.charCodeAt(i);
  }
  return bytes;
}

function writeWord(value) {
  return [value & 0xff, (value >> 8) & 0xff];
}

function writeLong(value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ];
}

function writeFloat(value) {
  const buffer = new ArrayBuffer(4);
  new DataView(buffer).setFloat32(0, value, true);
  return Array.from(new Uint8Array(buffer));
}

/** Representative temper-mill Msg 11 payload used by "Load sample". */
export const SAMPLE_VALUES = {
  'Msg Number': 11,
  Length: 168,
  'Sequence Number': 5,
  'Upper BR Diameter': 54.125,
  'Lower BR Diameter': 54.25,
  'Upper WR Diameter': 21.5,
  'Lower WR Diameter': 21.48,
  'Top Backup Roll Crown': 0.0025,
  'Top Backup Roll Roughness': 0.000032,
  'Top Work Roll Crown': 0.0018,
  'Top Work Roll Roughness': 0.000028,
  'Bottom Work Roll Crown': 0.0017,
  'Bottom Work Roll Roughness': 0.000029,
  'Bottom Backup Roll Crown': 0.0024,
  'Bottom Backup Roll Roughness': 0.000031,
  'Top Backup Roll ID': 'TBR-1042',
  'Top Work Roll ID': 'TWR-2218',
  'Bottom Work Roll ID': 'BWR-2219',
  'Bottom Backup Roll ID': 'BBR-1043',
};

export function encodeSampleBytes(values = SAMPLE_VALUES) {
  const bytes = [];
  for (const field of FIELDS) {
    const value = values[field.name];
    if (field.type === 'Word') bytes.push(...writeWord(value ?? 0));
    else if (field.type === 'Long') bytes.push(...writeLong(value ?? 0));
    else if (field.type === 'REAL') bytes.push(...writeFloat(value ?? 0));
    else if (field.type === 'Byte*16') bytes.push(...padString(value ?? '', field.size));
  }
  return bytes;
}

export function toWiresharkDump(bytes) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    const hex = slice.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = slice
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.'))
      .join('');
    const paddedHex = hex.padEnd(47, ' ');
    lines.push(`${offset.toString(16).padStart(4, '0')}  ${paddedHex}  ${ascii}`);
  }
  return lines.join('\n');
}

export function sampleHexDump() {
  return toWiresharkDump(encodeSampleBytes());
}

function be16(value) {
  return [(value >> 8) & 0xff, value & 0xff];
}

/** Ethernet + IPv4 + TCP (no options = 54 header bytes) wrapping a payload. */
export function wrapWithEthernetIpv4Tcp(payload, tcpOptionBytes = 0) {
  const eth = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x08, 0x00,
  ];
  const tcpHeaderLen = 20 + tcpOptionBytes;
  const ipTotal = 20 + tcpHeaderLen + payload.length;
  const ip = [
    0x45, 0x00,
    ...be16(ipTotal),
    0x00, 0x00,
    0x40, 0x00,
    0x40, 0x06,
    0x00, 0x00,
    0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x02,
  ];
  const tcp = [
    0x04, 0xd2,
    0x13, 0x88,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    ((tcpHeaderLen / 4) << 4), 0x18,
    0xff, 0xff,
    0x00, 0x00,
    0x00, 0x00,
  ];
  while (tcp.length < tcpHeaderLen) tcp.push(0);
  return [...eth, ...ip, ...tcp, ...payload];
}

export function wrapWithLeadingBytes(payload, count) {
  return [...Array.from({ length: count }, () => 0xaa), ...payload];
}
