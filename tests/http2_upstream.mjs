/** Exercise real HTTP/2 ALPN, bidirectional streaming, and gRPC-style trailers. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http2 from 'node:http2';
import { once } from 'node:events';

const [proxyPort, certificate, key, ca] = process.argv.slice(2);
const server = http2.createSecureServer({
  cert: fs.readFileSync(certificate),
  key: fs.readFileSync(key),
  allowHTTP1: false,
});
const sessions = new Set();
server.on('session', (session) => {
  sessions.add(session);
  session.on('close', () => sessions.delete(session));
});
server.on('stream', (stream, headers) => {
  assert.equal(stream.session.alpnProtocol, 'h2');
  assert.equal(headers.authorization, 'replacement');
  assert.equal(headers.te, 'trailers');
  assert.equal(headers[':path'], '/secure');
  let received = '';
  let receivedTrailers = false;
  stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
  stream.on('data', (chunk) => {
    received += chunk;
    // Respond before request completion: a buffering proxy will deadlock here.
    if (received === 'first') stream.write('first');
  });
  stream.on('trailers', (trailers) => {
    assert.equal(trailers['x-request-trailer'], 'request-complete');
    receivedTrailers = true;
  });
  stream.on('end', () => {
    assert.equal(received, 'firstsecond');
    assert.ok(receivedTrailers, 'proxy lost client request trailers');
    stream.end('second');
  });
  stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0', 'grpc-message': 'complete' }));
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const client = http2.connect(`https://localhost:${proxyPort}`, { ca: fs.readFileSync(ca) });
const deadline = setTimeout(() => { throw new Error('HTTP/2 streaming test timed out'); }, 10000);
try {
  await once(client, 'connect');
  assert.equal(client.alpnProtocol, 'h2');
  const request = client.request({
    ':method': 'GET', ':path': '/secure',
    ':authority': `localhost:${server.address().port}`, te: 'trailers',
  }, { endStream: false, waitForTrailers: true });
  let response = '';
  let sentSecond = false;
  let receivedTrailers = false;
  request.on('response', (headers) => assert.equal(headers[':status'], 200));
  request.on('data', (chunk) => {
    response += chunk;
    if (!sentSecond && response === 'first') {
      sentSecond = true;
      request.end('second');
    }
  });
  request.on('wantTrailers', () => request.sendTrailers({ 'x-request-trailer': 'request-complete' }));
  request.on('trailers', (trailers) => {
    assert.equal(trailers['grpc-status'], '0');
    assert.equal(trailers['grpc-message'], 'complete');
    receivedTrailers = true;
  });
  request.write('first');
  await once(request, 'end');
  assert.equal(response, 'firstsecond');
  assert.ok(receivedTrailers, 'proxy lost upstream response trailers');
  console.log('PASS: h2-only upstream ALPN, bidirectional streaming, request and gRPC response trailers');
} finally {
  clearTimeout(deadline);
  client.destroy();
  for (const session of sessions) session.destroy();
  await new Promise((resolve) => server.close(resolve));
}
