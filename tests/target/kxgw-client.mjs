#!/usr/bin/env node
// Minimal kxgw JSON-lines client for the target acceptance test (tests/target/kxgw.sh).
//   node kxgw-client.mjs <port> '<json line>' ['<json line>' ...]
//     sends each line, prints every response line, waits until each request's
//     last line ("done":true) arrived. Options (before the port):
//       --raw          send the lines verbatim (malformed input tests)
//       --listen <ms>  after the requests, keep printing pushed lines for <ms>
//       --timeout <ms> overall limit (default 60000)
import net from 'node:net';

const args = process.argv.slice(2);
let raw = false, listenMs = 0, timeoutMs = 60000;
while (args[0]?.startsWith('--')) {
  const a = args.shift();
  if (a === '--raw') raw = true;
  else if (a === '--listen') listenMs = Number(args.shift());
  else if (a === '--timeout') timeoutMs = Number(args.shift());
}
const port = Number(args.shift());
const lines = args;
const sock = net.connect(port, '127.0.0.1');
let buf = '', pending = 0, idx = 0, sentId;
const kill = setTimeout(() => { console.log('CLIENT-TIMEOUT'); process.exit(3); }, timeoutMs);

function sendNext() {
  if (idx >= lines.length) {
    setTimeout(() => { clearTimeout(kill); sock.end(); process.exit(0); }, listenMs);
    return;
  }
  pending = 1;
  try { sentId = JSON.parse(lines[idx]).id; } catch { sentId = undefined; }
  sock.write(lines[idx++] + '\n');
}
sock.on('connect', () => (lines.length ? sendNext() : setTimeout(() => process.exit(0), listenMs)));
sock.on('data', (d) => {
  buf += d.toString('latin1');
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    console.log(line);
    let m = null;
    try { m = JSON.parse(line); } catch { console.log('CLIENT-BAD-JSON'); }
    // a request with an id is answered by its own lines; pushed lines (no id)
    // only complete a request that had no id, or an error for an unparsable one
    const answersRequest = m && (sentId !== undefined ? m.id === sentId || (m.kind === 'error' && m.id === undefined) : true);
    if (pending && m && m.done && answersRequest) { pending = 0; sendNext(); }
  }
});
sock.on('error', (e) => { console.log(`CLIENT-ERROR ${e.code ?? e.message}`); process.exit(2); });
sock.on('close', () => { if (pending) { console.log('CLIENT-CLOSED'); process.exit(2); } });
