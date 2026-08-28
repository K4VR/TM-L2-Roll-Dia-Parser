# TM-L2-Roll-Dia-Parser

Temper Mill Level 2 **Msg 11 — Roll Parameters** parser. Paste a Wireshark hex dump (or a raw hex stream) from the PLC / Level 2 roll-diameter message and decode diameters, crowns, roughness, and roll IDs.

## Run locally

```bash
npm install
npm run dev
```

Then open the printed local URL (default `http://localhost:5173`).

```bash
npm test        # parser unit tests
npm run build   # production build
```

## Usage

1. In Wireshark, copy the TCP payload as a hex dump (or copy the bytes as a hex stream).
2. Paste into **Paste Wireshark Hex Dump**.
3. Click **Parse**.
4. Optionally **Export CSV**.

**Load sample** fills a representative little-endian Msg 11 frame so you can confirm the layout without a capture.

The parser accepts:

- Spaced or continuous hex streams (`0B 00 A8 00 …`)
- Wireshark hex dumps with offset + ASCII columns
- `hexdump -C` / `xxd` style lines

All multi-byte fields are **little-endian** (Word = uint16, Long = uint32, REAL = IEEE-754 float32). Roll IDs are 16-byte null-padded ASCII.

## Message layout (168 bytes)

| Offset | Field | Type | Size |
|--------|--------|------|------|
| 0 | Msg Number | Word | 2 |
| 2 | Length | Word | 2 |
| 4 | Sequence Number | Long | 4 |
| 8 | Upper / Lower BR & WR diameters | REAL | 4 × 4 |
| 24 | Crown / roughness (top & bottom WR/BR) | REAL | 8 × 4 |
| 56 | Top/Bottom WR/BR IDs | Byte×16 | 4 × 16 |
| 120 | Spare 1–12 | REAL | 12 × 4 |
