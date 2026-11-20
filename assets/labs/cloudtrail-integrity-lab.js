'use strict';

const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign, verify } = require('node:crypto');
const { gzipSync, gunzipSync } = require('node:zlib');

// Training format only. No AWS connections, credentials, or filesystem changes.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const original = gzipSync('{"Records":[{"eventName":"DescribeInstances"}]}\n');

function makeDigest(path, previous, logs) {
  const body = Buffer.from(JSON.stringify({ path, previous, logs }));
  return { body, signature: sign('sha256', body, privateKey) };
}

const first = makeDigest('training/10Z', null, [
  { key: 'example-log.json.gz', sha256: hash(gunzipSync(original)) }
]);
const anchor = makeDigest('training/11Z', {
  path: 'training/10Z',
  signature: first.signature.toString('hex')
}, []);

function examine({ digests, files, anchorSignature }) {
  let path = 'training/11Z';
  let signature = anchorSignature;
  let checked = 0;

  while (path) {
    if (!signature) return 'NO_ANCHOR_SIGNATURE';
    const digest = digests.get(path);
    if (!digest) return 'DIGEST_UNAVAILABLE';
    if (!verify('sha256', digest.body, publicKey, signature)) return 'BAD_DIGEST_SIGNATURE';
    const entry = JSON.parse(digest.body);
    if (entry.path !== path) return 'WRONG_DIGEST_PATH';
    for (const { key, sha256 } of entry.logs) {
      if (!files.has(key)) return 'LOG_UNAVAILABLE';
      if (hash(gunzipSync(files.get(key))) !== sha256) return 'LOG_HASH_MISMATCH';
      checked++;
    }
    signature = entry.previous ? Buffer.from(entry.previous.signature, 'hex') : null;
    path = entry.previous?.path;
  }
  return `VALID_FILES_${checked}`;
}

const logKey = 'example-log.json.gz';
const cases = [
  ['Normal chain with an empty newest digest', 'VALID_FILES_1', () => {}],
  ['Change gzip compression but keep the JSON bytes', 'VALID_FILES_1',
    ({ files }) => files.set(logKey, gzipSync(gunzipSync(original), { level: 0 }))],
  ['Change a whitespace byte in the JSON', 'LOG_HASH_MISMATCH',
    ({ files }) => files.set(logKey, gzipSync(Buffer.concat([gunzipSync(original), Buffer.from(' ')])))],
  ['Leave out the referenced log', 'LOG_UNAVAILABLE', ({ files }) => files.delete(logKey)],
  ['Leave out the earlier digest', 'DIGEST_UNAVAILABLE', ({ digests }) => digests.delete('training/10Z')],
  ['Edit a signed digest body', 'BAD_DIGEST_SIGNATURE',
    ({ digests }) => digests.set('training/10Z', { body: Buffer.concat([first.body, Buffer.from(' ')]) })],
  ['Lose the newest signature in export', 'NO_ANCHOR_SIGNATURE', (fixture) => { fixture.anchorSignature = null; }],
  ['Resolve a valid signed digest at the wrong location', 'WRONG_DIGEST_PATH', (fixture) => {
    const other = makeDigest('training/other', null, []);
    fixture.digests.set('training/11Z', other);
    fixture.anchorSignature = other.signature;
  }],
  ['An empty starting digest with a valid signature', 'VALID_FILES_0', (fixture) => {
    const empty = makeDigest('training/11Z', null, []);
    fixture.digests.set('training/11Z', empty);
    fixture.anchorSignature = empty.signature;
  }]
];

for (const [name, expected, change] of cases) {
  const fixture = {
    digests: new Map([['training/10Z', first], ['training/11Z', anchor]]),
    files: new Map([[logKey, original]]),
    anchorSignature: anchor.signature
  };
  change(fixture);
  const result = examine(fixture);
  assert.equal(result, expected, name);
  console.log(`${result} · ${name}`);
}
console.log(`${cases.length} synthetic cases passed.`);
