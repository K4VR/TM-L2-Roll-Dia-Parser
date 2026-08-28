# TM-L2-Roll-Dia-Parser

Temper Mill Level 2 **Msg 11 — Roll Parameters** parser. Paste a Wireshark hex dump (or a raw hex stream) from the PLC / Level 2 roll-diameter message and decode diameters, crowns, roughness, and roll IDs.

## Open in a browser (no npm)

You do **not** need Node or npm.

1. Download [`parser.html`](parser.html) from this repo (or clone the repo).
2. Double-click it, or open it in Chrome / Edge / Firefox (`File → Open`).

That file is self-contained. It works offline aside from optional system fonts.

## Usage

1. In Wireshark, copy the packet as a hex dump (the full frame is fine — Ethernet/TCP headers are skipped automatically).
2. Paste into **Paste Wireshark Hex Dump**.
3. Click **Parse**.
4. Optionally **Export CSV**.

**Load sample** fills a representative little-endian Msg 11 frame so you can confirm the layout without a capture.

The parser accepts:

- Spaced or continuous hex streams (`0B 00 A8 00 …`)
- Wireshark hex dumps with offset + ASCII columns
- `hexdump -C` / `xxd` style lines
- Full frames with a **54-byte Ethernet + IPv4 + TCP** prefix

**Skip first 54 bytes** is on by default so you can paste a raw packet without trimming. Uncheck it only if the dump is already just the Msg 11 payload and the start is detected wrong.

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

## Optional: develop with Node

Only if you want to change the parser source and rebuild `parser.html`:

```bash
npm install
npm test
npm run standalone   # regenerates parser.html
npm run dev          # Vite preview at http://localhost:5173
```
