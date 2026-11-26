'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { once } = require('node:events');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const http2 = require('node:http2');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { checkServerIdentity } = require('node:tls');

const ALPHA = 'alpha.example.test';
const BETA = 'beta.example.test';

function testCertificate(directory) {
  const key = join(directory, 'key.pem');
  const cert = join(directory, 'cert.pem');
  execFileSync('openssl', [
    'req', '-new', '-x509', '-nodes', '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:P-256', '-sha256', '-days', '1',
    '-subj', '/CN=' + ALPHA, '-addext', 'subjectAltName=DNS:' + ALPHA + ',DNS:' + BETA,
    '-keyout', key, '-out', cert,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

function get(session, host, port) {
  return new Promise((resolve, reject) => {
    const request = session.request({
      ':method': 'GET',
      ':scheme': 'https',
      ':authority': host + ':' + port,
      ':path': '/catalog',
    });
    let status;
    request.once('response', (headers) => { status = headers[':status']; });
    request.once('error', reject);
    request.once('end', () => resolve({ status, streamId: request.id }));
    request.resume();
    request.end();
  });
}

async function run(certificate) {
  const server = http2.createSecureServer({ ...certificate, minVersion: 'TLSv1.3' });
  const sessionIds = new WeakMap();
  const clients = [];
  const serverSessions = new Set();
  const records = [];
  let nextId = 0;

  server.on('session', (session) => {
    sessionIds.set(session, ++nextId);
    serverSessions.add(session);
    session.once('close', () => serverSessions.delete(session));
  });
  server.on('stream', (stream, headers) => {
    const socket = stream.session.socket;
    const authority = headers[':authority'];
    const route = socket.servername;
    const expected = route + ':' + server.address().port;
    const status = authority === expected ? 200 : 421;
    records.push({
      connection: sessionIds.get(stream.session),
      stream: stream.id,
      sni: route,
      alpn: socket.alpnProtocol,
      authority,
      status,
    });
    stream.respond({ ':status': status, 'content-length': '0' });
    stream.end();
  });

  try {
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address();

    async function connect(name) {
      const session = http2.connect('https://127.0.0.1:' + port, {
        servername: name,
        ca: certificate.cert,
        minVersion: 'TLSv1.3',
      });
      clients.push(session);
      session.on('error', () => {});
      session.setTimeout(5000, () => session.destroy(new Error('local HTTP/2 timeout')));
      await once(session, 'connect');
      return session;
    }

    const first = await connect(ALPHA);
    const peer = first.socket.getPeerCertificate();
    const initial = await get(first, ALPHA, port);
    const refused = await get(first, BETA, port);
    const second = await connect(BETA);
    const retried = await get(second, BETA, port);
    for (const record of records) console.log(JSON.stringify(record));

    assert.equal(records.length, 3);
    assert.equal(first.alpnProtocol, 'h2');
    assert.equal(second.alpnProtocol, 'h2');
    assert.ok(records.every((entry) => entry.alpn === 'h2'));
    assert.equal(first.socket.authorized, true);
    assert.equal(checkServerIdentity(ALPHA, peer), undefined);
    assert.equal(checkServerIdentity(BETA, peer), undefined);
    assert.deepEqual([initial.status, refused.status], [200, 421]);
    assert.deepEqual([initial.streamId, refused.streamId], [1, 3]);
    assert.equal(records[0].connection, records[1].connection);
    assert.equal(records[1].sni, ALPHA);
    assert.equal(records[1].authority, BETA + ':' + port);
    assert.equal(retried.status, 200);
    assert.equal(retried.streamId, initial.streamId);
    assert.notEqual(records[2].connection, records[0].connection);
    assert.equal(records[2].sni, BETA);
    console.log('4/4 HTTP/2 controls passed.');
  } finally {
    for (const session of clients) session.destroy();
    for (const session of serverSessions) session.destroy();
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
}

async function main() {
  const directory = mkdtempSync(join(tmpdir(), 'wiki-http2-'));
  try {
    await run(testCertificate(directory));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
