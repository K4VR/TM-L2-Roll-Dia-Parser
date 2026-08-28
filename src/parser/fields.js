/**
 * Msg 11 — Roll Parameters
 * Little-endian PLC / Level 2 binary layout.
 *
 * Word  = uint16 LE
 * Long  = uint32 LE
 * REAL  = IEEE-754 float32 LE
 * Byte*16 = ASCII, null-padded to 16 bytes
 */
export const FIELDS = [
  { name: 'Msg Number', desc: 'Msg identifier 11=Roll parameters', type: 'Word', size: 2 },
  { name: 'Length', desc: 'Total Length of the message', type: 'Word', size: 2 },
  { name: 'Sequence Number', desc: 'Incremented each message sent', type: 'Long', size: 4 },
  { name: 'Upper BR Diameter', desc: 'Upper backup roll diameter', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Lower BR Diameter', desc: 'Lower backup roll diameter', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Upper WR Diameter', desc: 'Upper work roll diameter', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Lower WR Diameter', desc: 'Lower work roll diameter', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Top Backup Roll Crown', desc: 'Upper backup roll crown', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Top Backup Roll Roughness', desc: 'Upper backup roll roughness', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Top Work Roll Crown', desc: 'Upper work roll crown', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Top Work Roll Roughness', desc: 'Upper work roll roughness', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Bottom Work Roll Crown', desc: 'Lower work roll crown', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Bottom Work Roll Roughness', desc: 'Lower work roll roughness', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Bottom Backup Roll Crown', desc: 'Lower backup roll crown', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Bottom Backup Roll Roughness', desc: 'Lower backup roll roughness', type: 'REAL', size: 4, unit: 'inch' },
  { name: 'Top Backup Roll ID', desc: 'Top Backup Roll ID', type: 'Byte*16', size: 16 },
  { name: 'Top Work Roll ID', desc: 'Top Work Roll ID', type: 'Byte*16', size: 16 },
  { name: 'Bottom Work Roll ID', desc: 'Bottom Work Roll ID', type: 'Byte*16', size: 16 },
  { name: 'Bottom Backup Roll ID', desc: 'Bottom Backup Roll ID', type: 'Byte*16', size: 16 },
  { name: 'Spare 1', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 2', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 3', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 4', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 5', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 6', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 7', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 8', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 9', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 10', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 11', desc: '', type: 'REAL', size: 4 },
  { name: 'Spare 12', desc: '', type: 'REAL', size: 4 },
];

export const EXPECTED_BYTES = FIELDS.reduce((sum, field) => sum + field.size, 0);

export const HEADER_FIELDS = new Set(['Msg Number', 'Length', 'Sequence Number']);

export function isRollId(type) {
  return type === 'Byte*16';
}

export function isSpare(name) {
  return name.startsWith('Spare');
}

export function isHeader(name) {
  return HEADER_FIELDS.has(name);
}
