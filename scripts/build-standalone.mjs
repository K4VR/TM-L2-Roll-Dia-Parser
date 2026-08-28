import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function stripModule(source) {
  return source
    .replace(/^import\s+[\s\S]*?from\s+['"][^'"]+['"];?\s*/gm, '')
    .replace(/^export\s+/gm, '');
}

const parserJs = [
  stripModule(readFileSync(join(root, 'src/parser/fields.js'), 'utf8')),
  stripModule(readFileSync(join(root, 'src/parser/parse.js'), 'utf8')),
  stripModule(readFileSync(join(root, 'src/parser/sample.js'), 'utf8')),
].join('\n');

const css = readFileSync(join(root, 'src/styles.css'), 'utf8');

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Roll Diameter Parser — Msg 11</title>
  <style>
${css}
    html, body { min-height: 100%; }
    #app { min-height: 100%; }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
${parserJs}

    const app = document.getElementById('app');
    let hexInput = '';
    let parsedData = null;
    let error = '';

    function rowClass(row) {
      if (isHeader(row.name)) return 'row-header';
      if (isRollId(row.type)) return 'row-rollid';
      if (isSpare(row.name)) return 'row-spare';
      return 'row-data';
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function parseHexDump() {
      error = '';
      try {
        parsedData = parseRollMessage(hexInput);
      } catch (err) {
        parsedData = null;
        error = err.message;
      }
      render();
    }

    function loadSample() {
      hexInput = sampleHexDump();
      error = '';
      parsedData = parseRollMessage(hexInput);
      render();
    }

    function exportToCSV() {
      if (!parsedData) return;
      const blob = new Blob([resultsToCsv(parsedData)], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = csvFilename();
      link.click();
      URL.revokeObjectURL(link.href);
    }

    function render() {
      const mismatch = parsedData && parsedData.totalBytes !== parsedData.expectedBytes
        ? ' (length mismatch — extra or missing payload bytes)'
        : '';

      const errorHtml = error ? '<div class="error">' + escapeHtml(error) + '</div>' : '';

      let resultsHtml = '';
      if (parsedData) {
        const rows = parsedData.results.map((row) => {
          const title = row.desc ? ' title="' + escapeHtml(row.desc) + '"' : '';
          return (
            '<tr class="' + rowClass(row) + '">' +
              '<td class="offset-cell">' + row.offset + '</td>' +
              '<td class="name-cell"' + title + '>' + escapeHtml(row.name) + '</td>' +
              '<td class="muted">' + escapeHtml(row.type) + '</td>' +
              '<td class="muted size-cell">' + row.size + '</td>' +
              '<td class="hex-cell">' + escapeHtml(row.rawHex) + '</td>' +
              '<td class="val-cell">' + escapeHtml(row.value) + '</td>' +
              '<td class="muted">' + escapeHtml(row.unit || '') + '</td>' +
            '</tr>'
          );
        }).join('');

        resultsHtml =
          '<div class="meta">Parsed ' + parsedData.totalBytes +
          ' bytes — expected ' + parsedData.expectedBytes + ' bytes' + mismatch + '</div>' +
          '<div class="table-shell"><div class="table-scroll"><table>' +
          '<thead><tr>' +
          '<th>Offset</th><th>Field Name</th><th>Type</th><th>Size</th>' +
          '<th>Raw Hex</th><th>Value</th><th>Unit</th>' +
          '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
      }

      const emptyHtml = (!parsedData && !error)
        ? '<div class="empty">Paste hex data above and click Parse to decode roll parameter message</div>'
        : '';

      app.innerHTML =
        '<div class="page"><div class="wrap">' +
          '<div class="title-row">' +
            '<h1>Roll Diameter Parser</h1>' +
            '<span class="msg-tag">Msg 11 — Roll Parameters</span>' +
          '</div>' +
          '<div class="input-card">' +
            '<label for="hex-input">Paste Wireshark Hex Dump</label>' +
            '<textarea id="hex-input" placeholder="0000  0b 00 a8 00 05 00 00 00 00 00 59 42  ...">' +
              escapeHtml(hexInput) +
            '</textarea>' +
            '<div class="btn-row">' +
              '<button class="parse-btn" type="button" id="parse-btn">Parse</button>' +
              '<button class="csv-btn" type="button" id="csv-btn"' + (parsedData ? '' : ' disabled') + '>Export CSV</button>' +
              '<button class="sample-btn" type="button" id="sample-btn">Load sample</button>' +
            '</div>' +
          '</div>' +
          errorHtml + resultsHtml + emptyHtml +
        '</div></div>';

      const textarea = document.getElementById('hex-input');
      textarea.addEventListener('input', (e) => { hexInput = e.target.value; });
      document.getElementById('parse-btn').addEventListener('click', parseHexDump);
      document.getElementById('csv-btn').addEventListener('click', exportToCSV);
      document.getElementById('sample-btn').addEventListener('click', loadSample);
    }

    render();
  </script>
</body>
</html>
`;

const out = join(root, 'parser.html');
writeFileSync(out, html);
console.log('Wrote', out);
