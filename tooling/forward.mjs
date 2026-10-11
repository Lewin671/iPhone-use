// Authenticated loopback HTTP gateway; the device also authenticates every request.
import http from 'node:http';
import iosDevice from 'appium-ios-device';
import { createConnector, createUSBConnector } from './device-transport.mjs';
import { AUTH_PROTOCOL, loadToken, authorized, authenticateSocket } from './auth.mjs';

const [udid, localArgument = '18100', deviceArgument = '8100'] = process.argv.slice(2);
if (!/^[A-Za-z0-9-]{8,64}$/.test(udid ?? '')) throw new Error('Provide a valid device UDID.');
function port(value) {
  if (!/^\d+$/.test(value)) throw new Error('Ports must be integers.');
  const number = Number(value);
  if (number < 1024 || number > 65535) throw new Error('Ports must be 1024-65535.');
  return number;
}
const localPort = port(localArgument), devicePort = port(deviceArgument);
const token = loadToken();
const connect = createConnector(createUSBConnector(iosDevice.Usbmux));
const sockets = new Set();
const agent = new http.Agent({ keepAlive: true, maxSockets: 16, maxFreeSockets: 2 });
agent.createConnection = (_options, callback) => {
  connect(udid, devicePort).then(socket => authenticateSocket(socket, token, devicePort)).then(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    callback(null, socket);
  }, () => callback(new Error('Device connection unavailable.')));
};
function reject(response, status, code) {
  if (response.destroyed) return;
  if (response.headersSent) { response.destroy(); return; }
  response.writeHead(status, { 'Content-Type': 'application/json', 'X-IPhone-Use-Auth': AUTH_PROTOCOL, Connection: 'close' });
  response.end(JSON.stringify({ value: { error: code, message: 'Authenticated device connection required.' } }));
}
const server = http.createServer({ maxHeaderSize: 8192 }, (request, response) => {
  const allowedHosts = [`127.0.0.1:${localPort}`, `localhost:${localPort}`];
  const authHeaders = request.rawHeaders.filter((_, i) => i % 2 === 0 && request.rawHeaders[i].toLowerCase() === 'authorization');
  if (!allowedHosts.includes(request.headers.host) || request.headers.origin !== undefined || authHeaders.length !== 1 ||
      !authorized(request.headers.authorization, token)) {
    reject(response, 401, 'authentication required'); request.resume(); return;
  }
  if (!['GET', 'POST', 'DELETE'].includes(request.method) || !/^\/[A-Za-z0-9_/%?.=&-]*$/.test(request.url)) {
    reject(response, 400, 'invalid request'); request.resume(); return;
  }
  const chunks = []; let size = 0, upstream;
  request.on('data', data => {
    size += data.length;
    if (size > 1024 * 1024) { reject(response, 413, 'request too large'); request.destroy(); }
    else chunks.push(data);
  });
  request.on('error', () => upstream?.destroy());
  request.on('end', () => {
    if (response.writableEnded || response.destroyed) return;
    const body = Buffer.concat(chunks);
    upstream = http.request({ host: '127.0.0.1', port: devicePort, method: request.method,
      path: request.url, agent, headers: { Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json', 'Content-Length': body.length } }, incoming => {
      if (incoming.headers['x-iphone-use-auth'] !== AUTH_PROTOCOL) {
        incoming.destroy(); reject(response, 502, 'authentication_required'); return;
      }
      response.writeHead(incoming.statusCode, { 'Content-Type': 'application/json', 'X-IPhone-Use-Auth': AUTH_PROTOCOL,
        'X-IPhone-Use-Transport': upstream.socket.iphoneUseTransport ?? 'unknown' });
      let bytes = 0;
      incoming.on('data', data => { bytes += data.length; if (bytes > 24 * 1024 * 1024) incoming.destroy(); });
      incoming.on('error', () => response.destroy());
      incoming.pipe(response);
    });
    upstream.on('socket', socket => socket.resume());
    upstream.setTimeout(15000, () => upstream.destroy());
    upstream.on('error', () => reject(response, 502, request.method === 'GET' ? 'pua_unreachable' : 'action_uncertain'));
    response.on('close', () => { if (!response.writableFinished) upstream.destroy(); });
    upstream.end(body); // A failed connection never reconnects/replays this request.
  });
});
server.headersTimeout = 5000; server.requestTimeout = 15000; server.maxConnections = 16;
server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
server.on('error', () => { console.error('Authenticated device gateway could not listen.'); process.exitCode = 1; stop(); });
server.listen(localPort, '127.0.0.1', () => console.log(`Authenticated device gateway listening at 127.0.0.1:${localPort}`));
function stop() {
  agent.destroy(); for (const socket of sockets) socket.destroy();
  server.close(() => process.exit(process.exitCode ?? 0));
  setTimeout(() => process.exit(process.exitCode ?? 0), 1000).unref();
}
process.on('SIGINT', stop); process.on('SIGTERM', stop);
