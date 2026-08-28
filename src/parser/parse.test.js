import { describe, expect, it } from 'vitest';
import { EXPECTED_BYTES, FIELDS } from './fields.js';
import {
  csvFilename,
  findPayloadStart,
  formatParseSummary,
  hexToBytes,
  parseRollMessage,
  readFloat,
  readLong,
  readWord,
  resultsToCsv,
  tcpPayloadOffset,
} from './parse.js';
import {
  encodeSampleBytes,
  SAMPLE_VALUES,
  sampleHexDump,
  toWiresharkDump,
  wrapWithEthernetIpv4Tcp,
  wrapWithLeadingBytes,
} from './sample.js';

function field(parsed, name) {
  return parsed.results.find((row) => row.name === name);
}

describe('little-endian readers', () => {
  it('reads Word and Long little-endian', () => {
    expect(readWord([0x0b, 0x00], 0)).toBe(11);
    expect(readWord([0xa8, 0x00], 0)).toBe(168);
    expect(readLong([0x05, 0x00, 0x00, 0x00], 0)).toBe(5);
  });

  it('reads IEEE-754 float32 little-endian', () => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setFloat32(0, 54.125, true);
    const bytes = Array.from(new Uint8Array(buf));
    expect(readFloat(bytes, 0)).toBeCloseTo(54.125, 5);
  });
});

describe('hexToBytes', () => {
  it('parses a spaced hex stream without treating the first byte as an offset', () => {
    const bytes = hexToBytes('0B 00 88 00 05 00 00 00');
    expect(bytes).toEqual([0x0b, 0x00, 0x88, 0x00, 0x05, 0x00, 0x00, 0x00]);
  });

  it('parses a continuous hex stream', () => {
    expect(hexToBytes('0b008800')).toEqual([0x0b, 0x00, 0x88, 0x00]);
  });

  it('strips Wireshark offsets and ASCII so payload IDs are not doubled', () => {
    const dump = sampleHexDump();
    const fromDump = hexToBytes(dump);
    const fromRaw = encodeSampleBytes();
    expect(fromDump).toEqual(fromRaw);
    expect(fromDump).toHaveLength(EXPECTED_BYTES);
  });

  it('parses hexdump -C with a mid-line gap and |ascii| trailer', () => {
    const bytes = encodeSampleBytes().slice(0, 16);
    const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const left = bytes
      .slice(0, 8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const right = bytes
      .slice(8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const ascii = bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    const line = `00000000  ${left}  ${right}  |${ascii}|`;
    expect(hexToBytes(line)).toEqual(bytes);
    expect(hex.split(' ').length).toBe(16);
  });

  it('parses xxd grouped-hex lines', () => {
    const bytes = encodeSampleBytes().slice(0, 16);
    const groups = [];
    for (let i = 0; i < bytes.length; i += 2) {
      groups.push(
        bytes
          .slice(i, i + 2)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
      );
    }
    const ascii = bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    const line = `00000000: ${groups.join(' ')}  ${ascii}`;
    expect(hexToBytes(line)).toEqual(bytes);
  });
});

describe('parseRollMessage', () => {
  it('decodes the sample payload field-for-field', () => {
    const parsed = parseRollMessage(toWiresharkDump(encodeSampleBytes()));
    expect(parsed.totalBytes).toBe(EXPECTED_BYTES);
    expect(parsed.expectedBytes).toBe(EXPECTED_BYTES);
    expect(parsed.results).toHaveLength(FIELDS.length);

    expect(field(parsed, 'Msg Number').value).toBe('11');
    expect(field(parsed, 'Length').value).toBe('168');
    expect(field(parsed, 'Sequence Number').value).toBe('5');
    expect(Number(field(parsed, 'Upper BR Diameter').value)).toBeCloseTo(54.125, 5);
    expect(Number(field(parsed, 'Lower WR Diameter').value)).toBeCloseTo(21.48, 5);
    expect(field(parsed, 'Top Backup Roll ID').value).toBe(SAMPLE_VALUES['Top Backup Roll ID']);
    expect(field(parsed, 'Bottom Backup Roll ID').value).toBe(SAMPLE_VALUES['Bottom Backup Roll ID']);
    expect(field(parsed, 'Upper BR Diameter').offset).toBe(8);
    expect(field(parsed, 'Top Backup Roll ID').offset).toBe(56);
    expect(field(parsed, 'Spare 1').offset).toBe(120);
  });

  it('marks trailing fields missing when the dump is truncated after the header', () => {
    const parsed = parseRollMessage('0B 00 A8 00 05 00 00 00');
    expect(field(parsed, 'Msg Number').hasData).toBe(true);
    expect(field(parsed, 'Sequence Number').hasData).toBe(true);
    expect(field(parsed, 'Upper BR Diameter').hasData).toBe(false);
    expect(field(parsed, 'Upper BR Diameter').value).toBe('—');
  });

  it('throws when fewer than 8 header bytes are present', () => {
    expect(() => parseRollMessage('0B 00')).toThrow(/too short/i);
  });

  it('skips a 54-byte Ethernet+IPv4+TCP prefix on a full-frame paste', () => {
    const payload = encodeSampleBytes();
    const frame = wrapWithEthernetIpv4Tcp(payload);
    expect(frame.length - payload.length).toBe(54);
    expect(tcpPayloadOffset(frame)).toBe(54);

    const parsed = parseRollMessage(toWiresharkDump(frame));
    expect(parsed.skippedBytes).toBe(54);
    expect(parsed.totalBytes).toBe(EXPECTED_BYTES);
    expect(field(parsed, 'Msg Number').value).toBe('11');
    expect(Number(field(parsed, 'Upper BR Diameter').value)).toBeCloseTo(54.125, 5);
    expect(field(parsed, 'Top Backup Roll ID').value).toBe('TBR-1042');
    expect(formatParseSummary(parsed)).toContain('Skipped 54 framing bytes');
  });

  it('skips a 54-byte opaque prefix when Msg 11 starts after it', () => {
    const parsed = parseRollMessage(toWiresharkDump(wrapWithLeadingBytes(encodeSampleBytes(), 54)));
    expect(parsed.skippedBytes).toBe(54);
    expect(field(parsed, 'Msg Number').value).toBe('11');
    expect(field(parsed, 'Sequence Number').value).toBe('5');
  });

  it('does not skip bytes when the paste is already the Msg 11 payload', () => {
    const parsed = parseRollMessage(sampleHexDump());
    expect(parsed.skippedBytes).toBe(0);
    expect(findPayloadStart(encodeSampleBytes())).toBe(0);
  });

  it('skips Ethernet+TCP headers that include TCP options', () => {
    const frame = wrapWithEthernetIpv4Tcp(encodeSampleBytes(), 12);
    expect(tcpPayloadOffset(frame)).toBe(66);
    const parsed = parseRollMessage(toWiresharkDump(frame));
    expect(parsed.skippedBytes).toBe(66);
    expect(field(parsed, 'Msg Number').value).toBe('11');
  });

  it('still skips 54 bytes when offset 0 looks like a false Msg 11 (0B 00 A8 00 MAC)', () => {
    const frame = wrapWithEthernetIpv4Tcp(encodeSampleBytes());
    frame[0] = 0x0b;
    frame[1] = 0x00;
    frame[2] = 0xa8;
    frame[3] = 0x00;
    const parsed = parseRollMessage(toWiresharkDump(frame));
    expect(parsed.skippedBytes).toBe(54);
    expect(field(parsed, 'Msg Number').value).toBe('11');
    expect(field(parsed, 'Length').value).toBe('168');
    expect(field(parsed, 'Top Backup Roll ID').value).toBe('TBR-1042');
  });

  it('force-skips 54 bytes when auto-detect would stay at 0 on a long paste', () => {
    const prefix = Array.from({ length: 54 }, () => 0x11);
    const parsed = parseRollMessage(
      toWiresharkDump([...prefix, ...encodeSampleBytes()]),
      { forceSkip54: true },
    );
    expect(parsed.skippedBytes).toBe(54);
    expect(field(parsed, 'Msg Number').value).toBe('11');
  });

  it('parses a single-space Wireshark dump without treating offsets as payload', () => {
    const frame = wrapWithEthernetIpv4Tcp(encodeSampleBytes());
    const lines = [];
    for (let offset = 0; offset < frame.length; offset += 16) {
      const slice = frame.slice(offset, offset + 16);
      const hex = slice.map((b) => b.toString(16).padStart(2, '0')).join(' ');
      lines.push(`${offset.toString(16).padStart(4, '0')} ${hex}`);
    }
    const parsed = parseRollMessage(lines.join('\n'));
    expect(parsed.skippedBytes).toBe(54);
    expect(parsed.totalBytes).toBe(EXPECTED_BYTES);
    expect(field(parsed, 'Msg Number').value).toBe('11');
  });
});

describe('csv export', () => {
  it('quotes fields and names the file with a timestamp', () => {
    const parsed = parseRollMessage(sampleHexDump());
    const csv = resultsToCsv(parsed);
    expect(csv.startsWith('Field Name,Description,Data Type')).toBe(true);
    expect(csv).toContain('"Top Backup Roll ID"');
    expect(csv).toContain('"TBR-1042"');
    expect(csvFilename(new Date('2026-08-28T18:24:00.000Z'))).toBe(
      'roll_diameter_parsed_2026-08-28T18-24-00.csv',
    );
  });
});
