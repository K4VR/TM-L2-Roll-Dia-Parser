import { useState } from 'react';
import { isHeader, isRollId, isSpare } from './parser/fields.js';
import { csvFilename, formatParseSummary, parseRollMessage, resultsToCsv } from './parser/parse.js';
import { sampleHexDump } from './parser/sample.js';

export default function App() {
  const [hexInput, setHexInput] = useState('');
  const [parsedData, setParsedData] = useState(null);
  const [error, setError] = useState('');

  const parseHexDump = () => {
    setError('');
    try {
      setParsedData(parseRollMessage(hexInput));
    } catch (err) {
      setParsedData(null);
      setError(err.message);
    }
  };

  const loadSample = () => {
    setHexInput(sampleHexDump());
    setError('');
    setParsedData(parseRollMessage(sampleHexDump()));
  };

  const exportToCSV = () => {
    if (!parsedData) return;
    const blob = new Blob([resultsToCsv(parsedData)], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = csvFilename();
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const rowClass = (row) => {
    if (isHeader(row.name)) return 'row-header';
    if (isRollId(row.type)) return 'row-rollid';
    if (isSpare(row.name)) return 'row-spare';
    return 'row-data';
  };

  return (
    <div className="page">
      <div className="wrap">
        <div className="title-row">
          <h1>Roll Diameter Parser</h1>
          <span className="msg-tag">Msg 11 — Roll Parameters</span>
        </div>

        <div className="input-card">
          <label htmlFor="hex-input">Paste Wireshark Hex Dump</label>
          <textarea
            id="hex-input"
            value={hexInput}
            onChange={(e) => setHexInput(e.target.value)}
            placeholder="0000  0b 00 a8 00 05 00 00 00 00 00 59 42  ..."
          />
          <div className="btn-row">
            <button className="parse-btn" type="button" onClick={parseHexDump}>
              Parse
            </button>
            <button className="csv-btn" type="button" onClick={exportToCSV} disabled={!parsedData}>
              Export CSV
            </button>
            <button className="sample-btn" type="button" onClick={loadSample}>
              Load sample
            </button>
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        {parsedData && (
          <>
            <div className="meta">{formatParseSummary(parsedData)}</div>
            <div className="table-shell">
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Offset</th>
                      <th>Field Name</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th>Raw Hex</th>
                      <th>Value</th>
                      <th>Unit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsedData.results.map((row) => (
                      <tr key={`${row.name}-${row.offset}`} className={rowClass(row)}>
                        <td className="offset-cell">{row.offset}</td>
                        <td className="name-cell" title={row.desc || undefined}>
                          {row.name}
                        </td>
                        <td className="muted">{row.type}</td>
                        <td className="muted size-cell">{row.size}</td>
                        <td className="hex-cell">{row.rawHex}</td>
                        <td className="val-cell">{row.value}</td>
                        <td className="muted">{row.unit || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {!parsedData && !error && (
          <div className="empty">
            Paste hex data above and click Parse to decode roll parameter message
          </div>
        )}
      </div>
    </div>
  );
}
