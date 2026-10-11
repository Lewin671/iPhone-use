// Credentials never travel in argv, URLs, tool results or diagnostics.
import { openSync, readFileSync, fstatSync, closeSync, constants } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
export const AUTH_PROTOCOL = 'bearer-v1';
export function loadToken(path = process.env.IPHONE_USE_AUTH_FILE) {
  if (!path) throw new Error('Device authentication file is required.');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0 || info.size > 128)
      throw new Error('Device authentication file must be owner-only.');
    const token = readFileSync(fd, 'utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('Invalid device authentication file.');
    return token;
  } finally { closeSync(fd); }
}
export function authorized(value, token) {
  if (typeof value !== 'string') return false;
  const actual = Buffer.from(value), expected = Buffer.from(`Bearer ${token}`);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// Prove the service before any mutation is sent. WDA uses fixed Content-Length
// framing; rejecting unknown framing fails closed rather than guessing boundaries.
export function authenticateSocket(socket, token, port) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0), expected;
    const timer = setTimeout(() => finish(new Error('Device authentication timed out.')), 5000);
    function finish(error) {
      clearTimeout(timer); socket.off('data', data); socket.off('error', failed); socket.off('close', closed);
      if (error) { socket.destroy(); reject(error); }
      else { socket.pause(); resolve(socket); }
    }
    function failed() { finish(new Error('Device authentication unavailable.')); }
    function closed() { finish(new Error('Device authentication disconnected.')); }
    function data(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 1024 * 1024 + 8192) { failed(); return; }
      if (expected === undefined) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) { if (buffer.length > 8192) failed(); return; }
        if (end > 8192) { failed(); return; }
        const lines = buffer.subarray(0,end).toString('latin1').split('\r\n'), fields = {};
        if (!/^HTTP\/1\.[01] 200(?: |$)/.test(lines.shift())) { failed(); return; }
        for (const line of lines) {
          const at=line.indexOf(':'); if (at < 1) { failed(); return; }
          const name=line.slice(0,at).toLowerCase();
          if (name.trim() !== name || Object.hasOwn(fields,name)) { failed(); return; }
          fields[name]=line.slice(at+1).trim();
        }
        if (fields['x-iphone-use-auth'] !== AUTH_PROTOCOL || fields['transfer-encoding'] !== undefined ||
            fields.connection?.toLowerCase() === 'close' || !/^\d+$/.test(fields['content-length'] ?? '') ||
            Number(fields['content-length']) > 1024 * 1024) { failed(); return; }
        expected=end+4+Number(fields['content-length']);
      }
      if (buffer.length === expected) finish();
      else if (buffer.length > expected) failed();
    }
    socket.on('data',data);socket.once('error',failed);socket.once('close',closed);
    socket.resume();
    socket.write(`GET /status HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nAuthorization: Bearer ${token}\r\nConnection: keep-alive\r\n\r\n`);
  });
}
